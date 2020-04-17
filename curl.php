<?php

class Curl{
    public static $debug = false;

    /**
     * @param $url
     * @param $param 这个param不是curl的选项，是http请求的参数
     * @return bool|string|void
     * @throws Exception
     */
    public static function get($url, $param){
        return self::run([]);
    }

    /**
     * @param $url
     * @param $param 这个param不是curl的选项，是http请求的参数
     * @return bool|string|void
     * @throws Exception
     */
    public static function post($url, $param){
        return self::run([]);
    }


    /**
     *
     * run()->setOpt()->checkOpt()
     * @param array $curlOpt
     * @return bool|string|void
     * @throws Exception
     */
    public static function run(array $curlOpt){
        try{
            $sCurl = curl_init();
            self::setOpt($sCurl, $curlOpt);
            $result = curl_exec($sCurl);
            curl_close($sCurl);
        }catch (Exception $e){
            return self::dealErr($e->getMessage());
        }
        if(self::$debug){
            var_dump($result);
            die;
        }
        return $result;
    }

    private static function setOpt($sCurl, array $curlOpt){
        foreach ($curlOpt as $key => $value){
            if(self::checkSetOpt($key, $value) !== true){
                return false;
            }
            curl_setopt($sCurl, constant("URLOPT_" . strtoupper($key)), $value);
        }
        return true;
    }
    private static function checkSetOpt($key, $value){
        $hasErr = true;
        $rule = [];
        if(isset($rule[$key])){
            if(isset($rule[$key]['verify']) && isset($rule[$key]['value'])){
                switch ($rule[$key]['verify']){
                    case 'in':
                        if(!in_array($value, $rule[$key]['boundary'])) goto dealErr;
                        break;
                    case 'reg':
                        if(!preg_match($rule[$key]['boundary'], $value)) goto dealErr;
                        break;
                }
            }else{
                switch ($rule[$key]['type']){
                    case 'array':
                        if(!is_array($value)) goto dealErr;
                        break;
                }
            }
        }
        $hasErr = false;
        dealErr:
        if($hasErr){
            return self::dealErr("{$key}取值非法");
        }
        return !$hasErr;

    }

    /**
     * createSetOptRule()-> printArrayToCode()
     */
    public static function createSetOptRule(){
        $a = [
            "curl" =>['mute','netrc','connect-timeout','connect-timeout_ms'],
            "curl_connect" =>['forbid_reuse','fresh_connect','max-connects'],
            "curl_return"=>['return-transfer'],

            "执行时间" => ['timeout','timeout_ms'],
            "location" =>['auto_referer','follow-location','unrestricted_auth','max-re-dirs','post-re-dir'],
            "return_transfer" => ['binary_transfer'],
            "cookie_session" =>['cookie_session','cookie','cookie-file','cookie-JAR'],
            "ssl" => ['cert_info','ssl-false-start','ssl_enable_alpn','ssl_enable_npn','ssl_verify-peer','ssl_verify-status','ssl_options','ssl_verify-host','ssl-version','ca-info','ca-path'],
            "unix" =>['crlf'],
            "ip" => ['ip-resolve'],
            "DNS" => ['dns_use_global_cache','dns_cache_timeout','dns_interface','dns_local_IP4','dns_local_IP6'],
            "http_smtP_pop3" => ['connect_only'],
            "http" => ['fail-one-error','http-get','post','put','http-proxy-tunnel','http_version','http-auth','proxy-auth','proxy-port','proxy-type'],
            "ftp" =>['ftp_use_eprt','ftp_use_epsv','ftp_create_missing_dirs','ftp-list-only','transfer-text|ftp-ascII','ftp-ssl-auth','ftp_file-method',['ftp-append']],
            'tftp' => ['tftp_no_options'],
            "tcp" => ['tcp_no_delay','tcp_fast-open'],
            "file" => ['file-time',['path_as_is']],
            "header" => ['header',['header_out']],
            "速度" => ['low_speed_limit','low_speed_time','max_recv_speed_large','max_send_speed_large'],
            "port" =>['port'],
            "stream" => ['stream_weight'],
            "protocols" => ['protocols','default_protocol'],
            "ssh" => ['ssh_auth_types'],
            [ 'no-body','no-progress','no-signal','pipe-wait','safe_upload',
                'sasl_ir','upload','verbose','buffer-size','expect_100_timeout_ms',
                'header-opt','re-dir_protocols','resume_from','time-condition','time-value',
                'customer-request'
            ]

        ];

        //51-5=46  159-113=46
        $bool = [
            'auto-referer',//true时。根据Location重定向时，【自动设置header中的referer信息】
            'binary-transfer',//设为 TRUE ，将在启用 CURLOPT_RETURNTRANSFER 时，【返回原生的（Raw）输出】
            'cookie-session',//【设为 TRUE 时将开启新的一次 cookie 会话】。它将强制 libcurl 忽略之前会话时存的其他 cookie。 libcurl 在默认状况下无论是否为会话，都会储存、加载所有 cookie。会话 cookie 是指没有过期时间，只存活在会话之中。
            'cert-info',//TRUE 将在安全传输时输出 SSL 证书信息到 STDERR
            'connect_only',//TRUE 将让库执行所有需要的代理、验证、连接过程，但不传输数据。此选项用于 HTTP、SMTP 和 POP3
            'crlf',//启用时将Unix的换行符转换成回车换行符。
            'dns_use_global_cache',//TRUE 会启用一个全局的DNS缓存。此选项非线程安全的，默认已开启。
            'fail-one-error',//当 HTTP 状态码大于等于 400，TRUE 将将显示错误详情。 默认情况下将返回页面，忽略 HTTP 代码。
            'ssl_false-start',//TRUE 开启 TLS False Start （一种 TLS 握手优化方式）
            'file-time',//TRUE 时，会尝试获取远程文档中的修改时间信息。信息可通过curl_getinfo()函数的CURLINFO_FILETIME 选项获取
            'follow-location',//TRUE 时将会根据服务器返回 HTTP 头中的 "Location: " 重定向。（注意：这是递归的，"Location: " 发送几次就重定向几次，除非设置了 CURLOPT_MAXREDIRS，限制最大重定向次数。）。
            'forbid_reuse',//TRUE 在完成交互以后强制明确的断开连接，不能在连接池中重用。
            'fresh_connect',//TRUE 强制获取一个新的连接，而不是缓存中的连接。
            'ftp_use_eprt',//TRUE 时，当 FTP 下载时，使用 EPRT (和 LPRT)命令。 设置为 FALSE 时禁用 EPRT 和 LPRT，仅仅使用PORT 命令。
            'ftp_use_epsv',//TRUE 时，在FTP传输过程中，回到 PASV 模式前，先尝试 EPSV 命令。设置为 FALSE 时禁用 EPSV。
            'ftp_create_missing_dirs',//TRUE 时，当 ftp 操作不存在的目录时将创建它。
            'ftp-append',//TRUE 为追加写入文件，而不是覆盖。
            'tcp_no_delay',//TRUE 时禁用 TCP 的 Nagle 算法，就是减少网络上的小包数量
            'ftp-ascII',//CURLOPT_TRANSFERTEXT 的别名
            'ftp-list-only',//TRUE 时只列出 FTP 目录的名字
            'header',//启用时会将头文件的信息作为数据流输出
            'header_out',//TRUE 时追踪句柄的请求字符串。
            'http-get',//TRUE 时会设置 HTTP 的 method 为 GET，由于默认是 GET，所以只有 method 被修改时才需要这个选项。
            'http-proxy-tunnel',//TRUE 会通过指定的 HTTP 代理来传输
            'mute',//TRUE 时将完全静默，无论是何 cURL 函数
            'netrc',//TRUE 时，在连接建立时，访问~/.netrc文件获取用户名和密码来连接远程站点。
            'no-body',//TRUE 时将不输出 BODY 部分。同时 Mehtod 变成了 HEAD。修改为 FALSE 时不会变成 GET。
            'no-progress',//TRUE 时关闭 cURL 的传输进度。【默认true】
            'no-signal',//TRUE 时忽略所有的 cURL 传递给 PHP 进行的信号。在 SAPI 多线程传输时此项被默认启用，所以超时选项仍能使用。
            'path_as_is',//TRUE 不处理 dot dot sequences （即 ../ ）
            'pipe-wait',//TRUE 则等待 pipelining/multiplexing
            'post',//TRUE 时会发送 POST 请求，类型为：application/x-www-form-urlencoded，是 HTML 表单提交时最常见的一种
            'put',//TRUE 时允许 HTTP 发送文件。要被 PUT 的文件必须在 CURLOPT_INFILE和CURLOPT_INFILESIZE 中设置。
            'return-transfer',//TRUE 将curl_exec()获取的信息以字符串返回，而不是直接输出。
            'safe_upload',//TRUE 禁用 @ 前缀在 CURLOPT_POSTFIELDS 中发送文件。意味着 @ 可以在字段中安全得使用了。可使用 CURLFile 作为上传的代替。
            'sasl_ir',//TRUE 开启，收到首包(first packet)后发送初始的响应(initial response)。
            'ssl_enable_alpn',//FALSE 禁用 SSL 握手中的 ALPN (如果 SSL 后端的 libcurl 内建支持) 用于协商到 http2
            'ssl_enable_npn',//FALSE 禁用 SSL 握手中的 NPN(如果 SSL 后端的 libcurl 内建支持)，用于协商到 http2。
            'ssl_verify-peer',//FALSE 禁止 cURL 验证对等证书（peer'scertificate）。要验证的交换证书可以在 CURLOPT_CAINFO 选项中设置，或在 CURLOPT_CAPATH中设置证书目录。
            'ssl_verify-status',//TRUE 验证证书状态
            'tcp_fast-open',//TRUE 开启 TCP Fast Open。
            'tftp_no_options',//TRUE 不发送 TFTP 的 options 请求
            'transfer-text',//TRUE 对 FTP 传输使用 ASCII 模式。对于LDAP，它检索纯文本信息而非 HTML。在 Windows 系统上，系统不会把 STDOUT 设置成二进制 模式
            'unrestricted_auth',//TRUE 在使用CURLOPT_FOLLOWLOCATION重定向 header 中的多个 location 时继续发送用户名和密码信息，哪怕主机名已改变。
            'upload',//TRUE 准备上传。
            'verbose',//TRUE 会输出所有的信息，写入到STDERR，或在CURLOPT_STDERR中指定的文件
        ];
        //96-60=36  211-175=36
        $integer = [
            'buffer-size',//每次读入的缓冲的尺寸。当然不保证每次都会完全填满这个尺寸。
            'close-policy',//被废弃
            'connect-timeout',//在尝试连接时等待的秒数。设置为0，则无限等待。
            'connect-timeout_ms',//尝试连接等待的时间，以毫秒为单位。设置为0，则无限等待。如果 libcurl 编译时使用系统标准的名称解析器（ standard system name resolver），那部分的连接仍旧使用以秒计的超时解决方案，最小超时时间还是一秒钟
            'dns_cache_timeout',//设置在内存中缓存 DNS 的时间，默认为120秒（两分钟）。
            'expect_100_timeout_ms',//超时预计： 100毫秒内的 continue 响应默认为 1000 毫秒。
            'ftp-ssl-auth',//FTP验证方式（启用的时候）：CURLFTPAUTH_SSL (首先尝试SSL)，CURLFTPAUTH_TLS (首先尝试TLS)或CURLFTPAUTH_DEFAULT (让cURL 自个儿决定)。
            'header-opt',//
            'http_version',//CURL_HTTP_VERSION_NONE (默认值，让 cURL 自己判断使用哪个版本)，CURL_HTTP_VERSION_1_0 (强制使用 HTTP/1.0)或CURL_HTTP_VERSION_1_1 (强制使用 HTTP/1.1)。
            'http-auth',//使用的 HTTP 验证方法。选项有： CURLAUTH_BASIC、 CURLAUTH_DIGEST、 CURLAUTH_GSSNEGOTIATE、 CURLAUTH_NTLM、 CURLAUTH_ANY和 CURLAUTH_ANYSAFE。可以使用 | 位域(OR)操作符结合多个值，cURL 会让服务器选择受支持的方法，并选择最好的那个。CURLAUTH_ANY是 CURLAUTH_BASIC | CURLAUTH_DIGEST | CURLAUTH_GSSNEGOTIATE | CURLAUTH_NTLM 的别名。CURLAUTH_ANYSAFE 是 CURLAUTH_DIGEST | CURLAUTH_GSSNEGOTIATE | CURLAUTH_NTLM 的别名
            'infile-size',//希望传给远程站点的文件尺寸，字节(byte)为单位。注意无法用这个选项阻止 libcurl 发送更多的数据，确切发送什么取决于 CURLOPT_READFUNCTION。
            'low_speed_limit',//传输速度，每秒字节（bytes）数，根据CURLOPT_LOW_SPEED_TIME秒数统计是否因太慢而取消传输。
            'low_speed_time',//当传输速度小于CURLOPT_LOW_SPEED_LIMIT时(bytes/sec)，PHP会判断是否因太慢而取消传输。
            'max-connects',//允许的最大连接数量。达到限制时，会通过CURLOPT_CLOSEPOLICY决定应该关闭哪些连接。
            'max-re-dirs',//指定最多的 HTTP 重定向次数，这个选项是和CURLOPT_FOLLOWLOCATION一起使用的
            'port',// 用来指定连接端口。,
            'post-re-dir',//位掩码， 1 (301 永久重定向), 2 (302 Found) 和 4 (303 See Other) 设置 CURLOPT_FOLLOWLOCATION 时，什么情况下需要再次 HTTP POST 到重定向网址。
            'protocols',//CURLPROTO_*的位掩码。启用时，会限制 libcurl 在传输过程中可使用哪些协议。这将允许你在编译libcurl时支持众多协议，但是限制只用允许的子集。默认 libcurl 将使用所有支持的协议。参见CURLOPT_REDIR_PROTOCOLS。可用的协议选项为： CURLPROTO_HTTP、 CURLPROTO_HTTPS、 CURLPROTO_FTP、 CURLPROTO_FTPS、 CURLPROTO_SCP、 CURLPROTO_SFTP、 CURLPROTO_TELNET、 CURLPROTO_LDAP、 CURLPROTO_LDAPS、 CURLPROTO_DICT、 CURLPROTO_FILE、 CURLPROTO_TFTP、 CURLPROTO_ALL
            'proxy-auth',//HTTP 代理连接的验证方式。使用在CURLOPT_HTTPAUTH中的位掩码。当前仅仅支持 CURLAUTH_BASIC和CURLAUTH_NTLM。
            'proxy-port',//代理服务器的端口。端口也可以在CURLOPT_PROXY中设置。
            'proxy-type',//可以是 CURLPROXY_HTTP (默认值) CURLPROXY_SOCKS4、 CURLPROXY_SOCKS5、 CURLPROXY_SOCKS4A 或 CURLPROXY_SOCKS5_HOSTNAME。
            're-dir_protocols',//CURLPROTO_* 值的位掩码。如果被启用，位掩码会限制 libcurl 在 CURLOPT_FOLLOWLOCATION开启时，使用的协议。默认允许除 FILE 和 SCP 外所有协议。这和 7.19.4 前的版本无条件支持所有支持的协议不同。关于协议常量，请参照CURLOPT_PROTOCOLS
            'resume_from',//在恢复传输时，传递字节为单位的偏移量（用来断点续传）。
            'ssl_options',//
            'ssl_verify-host',//设置为 1 是检查服务器SSL证书中是否存在一个公用名(common name)。译者注：公用名(Common Name)一般来讲就是填写你将要申请SSL证书的域名 (domain)或子域名(sub domain)。设置成 2，会检查公用名是否存在，并且是否与提供的主机名匹配。 0 为不检查名称。在生产环境中，这个值应该是 2（默认值）。
            'ssl-version',//CURL_SSLVERSION_DEFAULT (0), CURL_SSLVERSION_TLSv1 (1), CURL_SSLVERSION_SSLv2 (2), CURL_SSLVERSION_SSLv3 (3), CURL_SSLVERSION_TLSv1_0 (4), CURL_SSLVERSION_TLSv1_1 (5) ， CURL_SSLVERSION_TLSv1_2 (6) 中的其中一个。
            'stream_weight',//设置 stream weight 数值 ( 1 和 256 之间的数字).
            'time-condition',//设置如何对待 CURLOPT_TIMEVALUE。使用 CURL_TIMECOND_IFMODSINCE，仅在页面 CURLOPT_TIMEVALUE 之后修改，才返回页面。没有修改则返回 "304 Not Modified" 头，假设设置了 CURLOPT_HEADER 为 TRUE。CURL_TIMECOND_IFUNMODSINCE则起相反的效果。默认为 CURL_TIMECOND_IFMODSINCE。
            'timeout',//允许 cURL 函数执行的最长秒数
            'timeout_ms',//设置cURL允许执行的最长毫秒数。如果 libcurl 编译时使用系统标准的名称解析器（ standard system name resolver），那部分的连接仍旧使用以秒计的超时解决方案，最小超时时间还是一秒钟。
            'time-value',//秒数，从 1970年1月1日开始。这个时间会被 CURLOPT_TIMECONDITION使。默认使用CURL_TIMECOND_IFMODSINCE。
            'max_recv_speed_large',//如果下载速度超过了此速度(以每秒字节数来统计) ，即传输过程中累计的平均数，传输就会降速到这个参数的值。默认不限速。
            'max_send_speed_large',//如果上传的速度超过了此速度(以每秒字节数来统计)，即传输过程中累计的平均数，传输就会降速到这个参数的值。默认不限速。
            'ssh_auth_types',//A bitmask consisting of one or more of CURLSSH_AUTH_PUBLICKEY, CURLSSH_AUTH_PASSWORD, CURLSSH_AUTH_HOST, CURLSSH_AUTH_KEYBOARD. Set to CURLSSH_AUTH_ANY to let libcurl pick one.
            'ip-resolve',//允许程序选择想要解析的 IP 地址类别。只有在地址有多种 ip 类别的时候才能用，可以的值有： CURL_IPRESOLVE_WHATEVER、 CURL_IPRESOLVE_V4、 CURL_IPRESOLVE_V6，默认是 CURL_IPRESOLVE_WHATEVER。
            'ftp_file-method',//告诉 curl 使用哪种方式来获取 FTP(s) 服务器上的文件。可能的值有： CURLFTPMETHOD_MULTICWD、 CURLFTPMETHOD_NOCWD 和 CURLFTPMETHOD_SINGLECWD。
        ];
        $string = [
            'ca-info',//一个保存着1个或多个用来让服务端验证的证书的文件名。这个参数仅仅在和CURLOPT_SSL_VERIFYPEER一起使用时才有意义。
            'ca-path',// 一个保存着多个CA证书的目录。这个选项是和CURLOPT_SSL_VERIFYPEER一起使用的。
            'cookie',//设定 HTTP 请求中"Cookie: "部分的内容。多个 cookie 用分号分隔，分号后带一个空格(例如， "fruit=apple; colour=red")。
            'cookie-file',//包含 cookie 数据的文件名，cookie 文件的格式可以是 Netscape 格式，或者只是纯 HTTP 头部风格，存入文件。如果文件名是空的，不会加载 cookie，但 cookie 的处理仍旧启用。
            'cookie-JAR',//连接结束后，比如，调用 curl_close 后，保存 cookie 信息的文件
            'customer-request',//HTTP 请求时，使用自定义的 Method 来代替"GET"或"HEAD"。对 "DELETE" 或者其他更隐蔽的 HTTP 请求有用。有效值如 "GET"，"POST"，"CONNECT"等等；也就是说，不要在这里输入整行 HTTP 请求。例如输入"GET /index.html HTTP/1.0\r\n\r\n"是不正确的
            'default_protocol',//URL不带协议的时候，使用的默认协议
            'dns_interface',//Set the name of the network interface that the DNS resolver should bind to.This must be an interface name (not an address).
            'dns_local_IP4',//Set the local IPv4 address that the resolver should bind to. The argumentshould contain a single numerical IPv4 address as a string.
            'dns_local_IP6',//Set the local IPv6 address that the resolver should bind to. The argumentshould contain a single numerical IPv6 address as a string.







        ];
        $array = [];
        $source = [];
        $function = [];

        $tmpBool = ['type' => 'bool','verify' => 'in', 'boundary' => [true, false, 1, 0]];
        $tmpInteger = ['type' => 'integer', 'verify' => 'reg', 'boundary' =>'/^[1-9][0-9]*$/'];
        $tmpString = ['type' => 'string'];
        $tmpArray = ['type' => 'array'];
        $tmpSource = ['type' => 'source'];
        $tmpFunction = ['type' => 'function'];

        $rules = [];
        foreach (['bool', 'integer', 'string', 'array', 'source', 'function'] as $type){
            foreach ($$type as $k => $v){
                $tmp = "tmp" . ucfirst($type);
                if(is_integer($k)){
                    $option = $v;
                    $optionValue = $$tmp;
                }else{
                    $option = $k;
                    $optionValue = $v + $$tmp;
                }
                $option = strtr($option, ['-' => '']);
                $rules[$option] = $optionValue;
            }
        }
        echo self::printArrayToCode($rules);
    }

    private static function printArrayToCode(array $array)
    {
        $str = "[";
        foreach ($array as $key => $value) {
            if(is_integer($key)){
                if(is_array($value)){
                    $str .= self::printArrayToCode($value);
                }else{
                    if ($value === true) {
                        $str .= "true";
                    } elseif ($value === false) {
                        $str .= "false";
                    } elseif ($value === 'true') {
                        $str .= "'true'";
                    } elseif ($value === 'false') {
                        $str .= "'false'";
                    } elseif ($value === NULL) {
                        $str .= "NULL";
                    } elseif (is_string($value)) {
                        $str .= "'{$value}'";
                    } else {
                        $str .= $value;
                    }
                }
            }else{
                if(is_array($value)){
                    $str .= "'{$key}'=>".self::printArrayToCode($value);
                }else{
                    $str .= "'{$key}'=>";
                    if ($value === true) {
                        $str .= "true";
                    } elseif ($value === false) {
                        $str .= "false";
                    } elseif ($value === 'true') {
                        $str .= "'true'";
                    } elseif ($value === 'false') {
                        $str .= "'false'";
                    } elseif ($value === NULL) {
                        $str .= "NULL";
                    } elseif (is_string($value)) {
                        $str .= "'{$value}'";
                    } else {
                        $str .= $value;
                    }
                }
            }
            $str .= ',';
        }
        $str = trim($str, ',');
        $str .= "]";
        return $str;
    }

    private static function dealErr($msg){
        throw new Exception($msg, 1);
    }
}