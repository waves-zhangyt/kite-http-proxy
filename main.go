package main

import (
	"bufio"
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/waves-zhangyt/kiteagent/agent/cmd"
	"github.com/waves-zhangyt/kiteagent/agent/util"
	"github.com/waves-zhangyt/kiteagent/agent/util/logs"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"time"
)

// 监听端口
var port = flag.Int("port", 7788, "监听端口")

// 辅助kiteManagerProxy时的kiteManagerProxyUrl基础url（类似 http://localhost:8899/kite/httpproxy/）。
// 当kiteManagerProxyUrl为空时，即视作通用的http代理服务器
var kiteManagerProxyUrl = flag.String("kiteManagerProxyUrl", "",
	"实际代理的kitemanager基础url，如http://localhost:8899/kite/httpproxy/")
var kAppId = flag.String("kAppId", "", "kite open api app appId")
var kSecret = flag.String("kSecret", "", "kite open api app secret")

// 改进kiteproxy,增加支持宿主机metrics不能以本地localhost方式访问的方法(直接应用agent ip替代)
var useUrlIpAsTarget = flag.Bool("useUrlIpAsTarget", false, "use url ip as target(the default is 127.0.0.1)")

func main() {

	flag.Parse()

	// 实际业务代理
	http.HandleFunc("/", func(writer http.ResponseWriter, request *http.Request) {

		requestUri := request.RequestURI
		start := time.Now()

		// endpoint定位
		targetUrl := request.RequestURI

		// 头信息
		head := make(map[string]string)

		// kiteManagerProxyUrl 专有
		if *kiteManagerProxyUrl != "" {
			ip, port, uri := GetHostAndPortAndUri(request.RequestURI)

			// ip规则 agentIp---tartgetIp
			// 如果没有分隔符"---"，则认为agentIp是ip本身,targetIp是节点本身
			agentIp := ip
			targetIp := "127.0.0.1"

			// 当格式为 agentIp---targetIp时
			sepIndex := strings.Index(ip, "---")
			if sepIndex != -1 {
				agentIp = ip[0:sepIndex]
				targetIp = ip[sepIndex+3:]
			}

			// 当要访问的端口没有绑定在127.0.0.1上时
			if *useUrlIpAsTarget {
				targetIp = agentIp
			}

			targetUrl = *kiteManagerProxyUrl + agentIp + "/" + targetIp + "/" + strconv.Itoa(port) + uri

			if *kAppId != "" && *kSecret != "" {
				timestamp := int(time.Now().Unix())
				timestampStr := strconv.Itoa(timestamp)
				feed := *kAppId + "-" + *kSecret + "-" + timestampStr
				tokenData := md5.Sum([]byte(feed))
				head["kAppId"] = *kAppId
				head["kAppToken"] = hex.EncodeToString(tokenData[:])
				head["kTimestamp"] = timestampStr
			}
		}

		for k, v := range request.Header {
			ck := k
			cv := v
			if ck == "Host" {
				continue
			}
			if ck == "Cache-Control" || ck == "If-Modified-Since" || ck == "If-None-Match" {
				continue
			}
			head[ck] = cv[0] // 暂时只取第一个
		}

		//把来源ip信息加入头信息
		remoteIp := getRemoteIp(request)
		head["X-Forwarded-For"] = remoteIp

		//body
		data := getBodyData(request)

		responseCode, respHeaders, _, respBody, errMsg := UniRequestWithResponseCode(request.Method, targetUrl, &head,
			data, 300)

		reHead := make(map[string][]string)
		json.Unmarshal([]byte(respHeaders), &reHead)
		for k, v := range reHead {
			ck := k
			cv := v
			for _, item := range cv {
				writer.Header().Set(ck, item)
			}
		}

		writer.WriteHeader(responseCode)

		if errMsg != "" {
			writer.Write([]byte(errMsg))
		} else {
			writer.Write(respBody)
		}

		end := time.Now()
		interval := end.Sub(start)
		intervalSec := fmt.Sprintf("%.3f", interval.Seconds())
		logs.Debug("%s %s %v %s", requestUri, remoteIp, responseCode, intervalSec)
	})

	// 个性化定制，目前只定义端口
	strPort := strconv.Itoa(*port)
	server := &http.Server{
		Addr: ":" + strPort,
	}

	// 启动服务
	go func() {
		logs.Info("启动服务，监听端口：%s", strPort)
		err := server.ListenAndServe()
		if err != nil {
			logs.Error(err)
			os.Exit(1)
		}
	}()

	//结束程序入口
	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt)
	for {
		select {
		case <-interrupt:
			logs.Info("interrupted, 正常结束")
			return
		}
	}

}

// 获取bady信息
func getBodyData(request *http.Request) []byte {
	var data []byte

	reader := bufio.NewReader(request.Body)
	defer request.Body.Close()
	data = make([]byte, request.ContentLength)
	io.ReadFull(reader, data)

	return data
}

// 刚开始参照java ee写的，结果对application/x-www-form-urlencoded go的http包并没有进行
// 键值对参数化处理，所以这个方法暂时仅供参考了
func getBodyDataLikeJava(request *http.Request) []byte {
	var data []byte

	//form信息
	if request.Header.Get("Content-Type") == "application/x-www-form-urlencoded" {
		var buf strings.Builder
		i := 0
		for k, v := range request.Form {
			ck := k
			cv := v
			buf.WriteString(ck)
			buf.WriteString("=")
			for idx, item := range cv {
				nitem := item
				buf.WriteString(nitem)
				if idx != len(cv)-1 {
					buf.WriteString(",")
				}
			}
			i++
			if i != len(request.Form) {
				buf.WriteString("&")
			}
		}
		postStr := buf.String()
		data = []byte(postStr)
	} else {
		reader := bufio.NewReader(request.Body)
		defer request.Body.Close()
		data = make([]byte, request.ContentLength)
		io.ReadFull(reader, data)
	}

	return data
}

// 根据url获取请求的ip、端口和uri
// url格式 http://centos7-local:9090/metrics
func GetHostAndPortAndUri(url string) (string, int, string) {
	startIdx := strings.Index(url, "://")
	tempStr := url[startIdx+3:]
	portSepIdx := strings.Index(tempStr, ":")
	var ip string
	var port int = 80

	pathStartIdx := strings.Index(tempStr, "/")
	// 假设必须有跟path
	if pathStartIdx == -1 {
		tempStr += "/"
		pathStartIdx = strings.Index(tempStr, "/")
	}

	if portSepIdx != -1 {
		ip = tempStr[0:portSepIdx]
		port, _ = strconv.Atoi(tempStr[portSepIdx+1 : pathStartIdx])
	} else {
		ip = tempStr[0:pathStartIdx]
		if strings.HasPrefix(url, "https") {
			port = 443
		}
	}
	uri := tempStr[pathStartIdx:]

	return ip, port, uri
}

func getRemoteIp(request *http.Request) string {
	remoteIp := request.RemoteAddr
	idx := strings.LastIndex(remoteIp, ":")
	if idx != -1 {
		remoteIp = remoteIp[0:idx]
	}

	return remoteIp
}

// 通用http请求 返回 （statusCode, 头信息的json字符串，[Content-Type, Content-Encoding]，body内容, err字符串）
func UniRequestWithResponseCode(method, url string, headers *map[string]string, body []byte, timeout int) (int, string, []string, []byte,
	string) {

	var client *http.Client
	if timeout <= 0 {
		client = &http.Client{
			//用cmd的默认超时时间
			Timeout: time.Duration(cmd.DefaultCmdTimeout) * time.Second,
		}
	} else {
		client = &http.Client{
			Timeout: time.Duration(timeout) * time.Second,
		}
	}

	var buf io.Reader
	if body != nil {
		buf = bytes.NewReader(body)
	}

	req, err := http.NewRequest(method, url, buf)
	if err != nil {
		util.Error.Println(err)
		return 500, "", []string{"", ""}, nil, err.Error()
	}

	if headers != nil {
		for k, v := range *headers {
			req.Header.Add(k, v)
		}
	}

	resp, err2 := client.Do(req)
	defer func() {
		if resp != nil && resp.Body != nil {
			resp.Body.Close()
		}
	}()
	if err2 != nil {
		util.Error.Printf("http 请求错误 %s\n", err2)
		return 500, "", []string{"", ""}, nil, err2.Error()
	}

	//打印返回的头信息
	headJsonBytes, _ := json.MarshalIndent(resp.Header, "", " ")
	head := string(headJsonBytes)

	contentType := resp.Header.Get("Content-Type")
	contentEncoding := resp.Header.Get("Content-Encoding")

	//打印返回的body信息
	body, err1 := ioutil.ReadAll(resp.Body)
	if err1 != nil {
		util.Error.Println(err1)
		return 500, head, []string{contentType, contentEncoding}, nil, ""
	}

	return resp.StatusCode, head, []string{contentType, contentEncoding}, body, ""
}
