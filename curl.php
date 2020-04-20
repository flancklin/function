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
        $howUse = [
            "curl" =>['mute','netrc','connect-timeout','connect-timeout_ms'],
            "curl_connect" =>['forbid_reuse','fresh_connect','max-connects'],
            "curl_return"=>['return-transfer'],
            "执行时间" => ['timeout','timeout_ms'],
            "location" =>['auto_referer','follow-location','unrestricted_auth','max-re-dirs','post-redir'],
            "return_transfer" => ['binary_transfer'],
            "cookie_session" =>['cookie_session','cookie','cookie-file','cookie-JAR'],
            "ssl" => ['cert_info','ssl-false-start','ssl_enable_alpn','ssl_enable_npn',
                'ssl_verify-peer','ssl_verify-status','ssl_options','ssl_verify-host',
                'ssl-version','ca-info','ca-path','key-pass-wd','random_file',
                'ssl_cipher_list','ssl-cert','ssl-cert-pass-wd','ssl-cert-type',
                'ssl-engine','ssl-engine_default','ssl-key','ssl-key-pass-wd','ssl-key-type'
                ],
            "unix" =>['crlf','unix_socket_path'],
            "ip" => ['ip-resolve'],
            "DNS" => ['dns_use_global_cache','dns_cache_timeout','dns_interface','dns_local_IP4','dns_local_IP6'],
            "http_smtP_pop3" => ['connect_only'],
            "http" => ['fail-on-error','http-get','post','put','http-proxy-tunnel',
                'http_version','http-auth','proxy-auth','proxy-port','proxy-type',
                'post-fields','proxy','proxy_service_name','proxy-user-pwd','range','referer'],
            "ftp" =>['ftp_use_eprt','ftp_use_epsv','ftp_create_missing_dirs','ftp-list-only','transfer-text|ftp-ascII',
                'ftp-ssl-auth','ftp_file-method','ftp-port','krb4-level',['ftp-append']],
            'tftp' => ['tftp_no_options'],
            "tcp" => ['tcp_no-delay','tcp_fast-open'],
            "file" => ['file-time',['path_as_is']],
            "header" => ['header','encoding','user-agent',['header_out']],
            "速度" => ['low_speed_limit','low_speed_time','max_recv_speed_large','max_send_speed_large'],
            "port" =>['port'],
            "stream" => ['stream_weight'],
            "protocols" => ['protocols','default_protocol'],
            "ssh" => ['ssh_auth_types','ssh_host_public_key_md5','ssh_public_key-file','ssh_private_key-file'],
            'other'=>[ 'no-body','no-progress','no-signal','pipe-wait','safe_upload',
                'sasl_ir','upload','verbose','buffer-size','expect_100_timeout_ms',
                'header-opt','re-dir_protocols','resume_from','time-condition','time-value',
                'custom-request','egd-socket','interface','login_options','pinned-public-key',
                'private','service_name'
            ]

        ];

        $list = [
            '__bool',
            'auto-referer'=>['comment'=>'true时。根据Location重定向时，【自动设置header中的referer信息】','type'=>'bool'],
            'binary-transfer'=>['comment'=>'设为 TRUE ，将在启用 CURLOPT_RETURNTRANSFER 时，【返回原生的（Raw）输出】','php_die'=>'5.1.3','type'=>'bool'],
            'cookie-session'=>['comment'=>'【设为 TRUE 时将开启新的一次 cookie 会话】。它将强制 libcurl 忽略之前会话时存的其他 cookie。 libcurl 在默认状况下无论是否为会话，都会储存、加载所有 cookie。会话 cookie 是指没有过期时间，只存活在会话之中。','type'=>'bool'],
            'cert-info'=>['comment'=>'TRUE 将在安全传输时输出 SSL 证书信息到 STDERR','curl_begin'=>'7.19.1','php_begin'=>'5.3.2','type'=>'bool'],
            'connect_only'=>['comment'=>'TRUE 将让库执行所有需要的代理、验证、连接过程，但不传输数据。此选项用于 HTTP、SMTP 和 POP3','curl_begin'=>'7.15.2','php_curl'=>'5.5.0','type'=>'bool'],
            'crlf'=>['comment'=>'启用时将Unix的换行符转换成回车换行符。','type'=>'bool'],
            'dns_use_global_cache'=>['comment'=>'TRUE 会启用一个全局的DNS缓存。此选项非线程安全的，默认已开启。','type'=>'bool'],
            'fail-on-error'=>['comment'=>'当 HTTP 状态码大于等于 400，TRUE 将将显示错误详情。 默认情况下将返回页面，忽略 HTTP 代码。','type'=>'bool'],
            'ssl_false-start'=>['comment'=>'TRUE 开启 TLS False Start （一种 TLS 握手优化方式）','curl_begin'=>'7.42.0','php_curl'=>'7.0.7','type'=>'bool'],
            'file-time'=>['comment'=>'TRUE 时，会尝试获取远程文档中的修改时间信息。信息可通过curl_getinfo()函数的CURLINFO_FILETIME 选项获取','type'=>'bool'],
            'follow-location'=>['comment'=>'TRUE 时将会根据服务器返回 HTTP 头中的 "Location: " 重定向。（注意：这是递归的，"Location: " 发送几次就重定向几次，除非设置了 CURLOPT_MAXREDIRS，限制最大重定向次数。）。','type'=>'bool'],
            'forbid_reuse'=>['comment'=>'TRUE 在完成交互以后强制明确的断开连接，不能在连接池中重用。','type'=>'bool'],
            'fresh_connect'=>['comment'=>'TRUE 强制获取一个新的连接，而不是缓存中的连接。','type'=>'bool'],
            'ftp_use_eprt'=>['comment'=>'TRUE 时，当 FTP 下载时，使用 EPRT (和 LPRT)命令。 设置为 FALSE 时禁用 EPRT 和 LPRT，仅仅使用PORT 命令。','type'=>'bool'],
            'ftp_use_epsv'=>['comment'=>'TRUE 时，在FTP传输过程中，回到 PASV 模式前，先尝试 EPSV 命令。设置为 FALSE 时禁用 EPSV。','type'=>'bool'],
            'ftp_create_missing_dirs'=>['comment'=>'TRUE 时，当 ftp 操作不存在的目录时将创建它。','type'=>'bool'],
            'ftp-append'=>['comment'=>'TRUE 为追加写入文件，而不是覆','type'=>'bool'],
            'tcp_no-delay'=>['comment'=>'TRUE 时禁用 TCP 的 Nagle 算法，就是减少网络上的小包','curl_begin'=>'7.11.2','php_curl'=>'5.2.1','type'=>'bool'],
            'ftp-ascII'=>['comment'=>'CURLOPT_TRANSFERTEXT 的','type'=>'bool'],
            'ftp-list-only'=>['comment'=>'TRUE 时只列出 FTP 目录的','type'=>'bool'],
            'header'=>['comment'=>'启用时会将头文件的信息作为数据流','type'=>'bool'],
            'header_out'=>['comment'=>'TRUE 时追踪句柄的请求字符','prefix'=>'curlinfo_','type'=>'bool'],
            'http-get'=>['comment'=>'TRUE 时会设置 HTTP 的 method 为 GET，由于默认是 GET，所以只有 method 被修改时才需要这个选','type'=>'bool'],
            'http-proxy-tunnel'=>['comment'=>'TRUE 会通过指定的 HTTP 代理来','type'=>'bool'],
            'mute'=>['comment'=>'TRUE 时将完全静默，无论是何 cURL ','curl_die'=>'7.15.5','type'=>'bool'],
            'netrc'=>['comment'=>'TRUE 时，在连接建立时，访问~/.netrc文件获取用户名和密码来连接远程站','type'=>'bool'],
            'no-body'=>['comment'=>'TRUE 时将不输出 BODY 部分。同时 Mehtod 变成了 HEAD。修改为 FALSE 时不会变成 GE','type'=>'bool'],
            'no-progress'=>['comment'=>'TRUE 时关闭 cURL 的传输进度。【默认tru','type'=>'bool'],
            'no-signal'=>['comment'=>'TRUE 时忽略所有的 cURL 传递给 PHP 进行的信号。在 SAPI 多线程传输时此项被默认启用，所以超时选项仍能使','curl_begin'=>'7.10.0','type'=>'bool'],
            'path_as_is'=>['comment'=>'TRUE 不处理 dot dot sequences （即 ../','curl_begin'=>'7.42.0','php_curl'=>'7.0.7','type'=>'bool'],
            'pipe-wait'=>['comment'=>'TRUE 则等待 pipelining/multiplexi','curl_begin'=>'7.43.0','php_curl'=>'7.0.7','type'=>'bool'],
            'post'=>['comment'=>'TRUE 时会发送 POST 请求，类型为：application/x-www-form-urlencoded，是 HTML 表单提交时最常见的','type'=>'bool'],
            'put'=>['comment'=>'TRUE 时允许 HTTP 发送文件。要被 PUT 的文件必须在 CURLOPT_INFILE和CURLOPT_INFILESIZE 中设','type'=>'bool'],
            'return-transfer'=>['comment'=>'TRUE 将curl_exec()获取的信息以字符串返回，而不是直接输','type'=>'bool'],
            'safe_upload'=>['comment'=>'TRUE 禁用 @ 前缀在 CURLOPT_POSTFIELDS 中发送文件。意味着 @ 可以在字段中安全得使用了。可使用 CURLFile 作为上传的代','php_begin'=>'5.5.0','php_die'=>'7.0.0','default'=>['php'=>['50500'=>false,'50600'=>true]],'type'=>'bool'],
            'sasl_ir'=>['comment'=>'TRUE 开启，收到首包(first packet)后发送初始的响应(initial response','curl_begin'=>'7.31.10','php_curl'=>'7.0.7','type'=>'bool'],
            'ssl_enable_alpn'=>['comment'=>'FALSE 禁用 SSL 握手中的 ALPN (如果 SSL 后端的 libcurl 内建支持) 用于协商到 http2','curl_begin'=>'7.36.0','php_curl'=>'7.0.7','type'=>'bool'],
            'ssl_enable_npn'=>['comment'=>'FALSE 禁用 SSL 握手中的 NPN(如果 SSL 后端的 libcurl 内建支持)，用于协商到 http2','curl_begin'=>'7.36.0','php_curl'=>'7.0.7','type'=>'bool'],
            'ssl_verify-peer'=>['comment'=>'FALSE 禁止 cURL 验证对等证书（peer scertificate）。要验证的交换证书可以在 CURLOPT_CAINFO 选项中设置，或在 CURLOPT_CAPATH中设置证书目','default'=>['curl'=>['71000'=>true]],'type'=>'bool'],
            'ssl_verify-status'=>['comment'=>'TRUE 验证证书','curl_begin'=>'7.41.0','php_begin'=>'7.0.7','type'=>'bool'],
            'tcp_fast-open'=>['comment'=>'TRUE 开启 TCP Fast Ope','curl_begin'=>'7.49.0','php_begin'=>'7.0.7','type'=>'bool'],
            'tftp_no_options'=>['comment'=>'TRUE 不发送 TFTP 的 options ','curl_begin'=>'7.48.0','php_begin'=>'7.0.7','type'=>'bool'],
            'transfer-text'=>['comment'=>'TRUE 对 FTP 传输使用 ASCII 模式。对于LDAP，它检索纯文本信息而非 HTML。在 Windows 系统上，系统不会把 STDOUT 设置成二进制 ','type'=>'bool'],
            'unrestricted_auth'=>['comment'=>'TRUE 在使用CURLOPT_FOLLOWLOCATION重定向 header 中的多个 location 时继续发送用户名和密码信息，哪怕主机名已改','type'=>'bool'],
            'upload'=>['comment'=>'TRUE 准备上','type'=>'bool'],
            'verbose'=>['comment'=>'TRUE 会输出所有的信息，写入到STDERR，或在CURLOPT_STDERR中指定的文件','type'=>'bool'],
            '__integer',
            'buffer-size'=>['comment'=>'每次读入的缓冲的尺寸。当然不保证每次都会完全填满这个尺寸。','curl_begin'=>'7.10.0','type'=>'integer'],
            'close-policy'=>['comment'=>'被废弃','php_die'=>'5.6.0','type'=>'integer'],
            'connect-timeout'=>['comment'=>'在尝试连接时等待的秒数。设置为0，则无限等待。','type'=>'integer'],
            'connect-timeout_ms'=>['comment'=>'尝试连接等待的时间，以毫秒为单位。设置为0，则无限等待。如果 libcurl 编译时使用系统标准的名称解析器（ standard system name resolver），那部分的连接仍旧使用以秒计的超时解决方案，最小超时时间还是一秒钟','curl_begin'=>'7.16.2','php_begin'=>'5.2.3','type'=>'integer'],
            'dns_cache_timeout'=>['comment'=>'设置在内存中缓存 DNS 的时间，默认为120秒（两分钟）。','type'=>'integer'],
            'expect_100_timeout_ms'=>['comment'=>'超时预计： 100毫秒内的 continue 响应默认为 1000 毫秒。','curl_begin'=>'7.36.0','php_begin'=>'7.0.7','type'=>'integer'],
            'ftp-ssl-auth'=>['comment'=>'FTP验证方式（启用的时候）：CURLFTPAUTH_SSL (首先尝试SSL)，CURLFTPAUTH_TLS (首先尝试TLS)或CURLFTPAUTH_DEFAULT (让cURL 自个儿决定)。','curl_begin'=>'7.12.2','type'=>'integer'],
            'header-opt'=>['comment'=>'','curl_begin'=>'7.37.0','php_begin'=>'7.0.7','type'=>'integer'],
            'http_version'=>['comment'=>'CURL_HTTP_VERSION_NONE (默认值，让 cURL 自己判断使用哪个版本)，CURL_HTTP_VERSION_1_0 (强制使用 HTTP/1.0)或CURL_HTTP_VERSION_1_1 (强制使用 HTTP/1.1)。','type'=>'integer'],
            'http-auth'=>['comment'=>'使用的 HTTP 验证方法。选项有： CURLAUTH_BASIC、 CURLAUTH_DIGEST、 CURLAUTH_GSSNEGOTIATE、 CURLAUTH_NTLM、 CURLAUTH_ANY和 CURLAUTH_ANYSAFE。可以使用 | 位域(OR)操作符结合多个值，cURL 会让服务器选择受支持的方法，并选择最好的那个。CURLAUTH_ANY是 CURLAUTH_BASIC | CURLAUTH_DIGEST | CURLAUTH_GSSNEGOTIATE | CURLAUTH_NTLM 的别名。CURLAUTH_ANYSAFE 是 CURLAUTH_DIGEST | CURLAUTH_GSSNEGOTIATE | CURLAUTH_NTLM 的别名','type'=>'integer'],
            'infile-size'=>['comment'=>'希望传给远程站点的文件尺寸，字节(byte)为单位。注意无法用这个选项阻止 libcurl 发送更多的数据，确切发送什么取决于 CURLOPT_READFUNCTION。','type'=>'integer'],
            'low_speed_limit'=>['comment'=>'传输速度，每秒字节（bytes）数，根据CURLOPT_LOW_SPEED_TIME秒数统计是否因太慢而取消传输。','type'=>'integer'],
            'low_speed_time'=>['comment'=>'当传输速度小于CURLOPT_LOW_SPEED_LIMIT时(bytes/sec)，PHP会判断是否因太慢而取消传输。','type'=>'integer'],
            'max-connects'=>['comment'=>'允许的最大连接数量。达到限制时，会通过CURLOPT_CLOSEPOLICY决定应该关闭哪些连接。','type'=>'integer'],
            'max-re-dirs'=>['comment'=>'指定最多的 HTTP 重定向次数，这个选项是和CURLOPT_FOLLOWLOCATION一起使用的','type'=>'integer'],
            'port'=>['comment'=>' 用来指定连接端口。,','type'=>'integer'],
            'post-redir'=>['comment'=>'位掩码， 1 (301 永久重定向), 2 (302 Found) 和 4 (303 See Other) 设置 CURLOPT_FOLLOWLOCATION 时，什么情况下需要再次 HTTP POST 到重定向网址。','curl_begin'=>'7.19.1','php_begin'=>'5.3.2','type'=>'integer'],
            'protocols'=>['comment'=>'CURLPROTO_*的位掩码。启用时，会限制 libcurl 在传输过程中可使用哪些协议。这将允许你在编译libcurl时支持众多协议，但是限制只用允许的子集。默认 libcurl 将使用所有支持的协议。参见CURLOPT_REDIR_PROTOCOLS。可用的协议选项为： CURLPROTO_HTTP、 CURLPROTO_HTTPS、 CURLPROTO_FTP、 CURLPROTO_FTPS、 CURLPROTO_SCP、 CURLPROTO_SFTP、 CURLPROTO_TELNET、 CURLPROTO_LDAP、 CURLPROTO_LDAPS、 CURLPROTO_DICT、 CURLPROTO_FILE、 CURLPROTO_TFTP、 CURLPROTO_ALL','curl_begin'=>'7.19.4','type'=>'integer'],
            'proxy-auth'=>['comment'=>'HTTP 代理连接的验证方式。使用在CURLOPT_HTTPAUTH中的位掩码。当前仅仅支持 CURLAUTH_BASIC和CURLAUTH_NTLM。','curl_begin'=>'7.10.7','type'=>'integer'],
            'proxy-port'=>['comment'=>'代理服务器的端口。端口也可以在CURLOPT_PROXY中设置。','type'=>'integer'],
            'proxy-type'=>['comment'=>'可以是 CURLPROXY_HTTP (默认值) CURLPROXY_SOCKS4、 CURLPROXY_SOCKS5、 CURLPROXY_SOCKS4A 或 CURLPROXY_SOCKS5_HOSTNAME。','curl_begin'=>'7.10.0','type'=>'integer'],
            're-dir_protocols'=>['comment'=>'CURLPROTO_* 值的位掩码。如果被启用，位掩码会限制 libcurl 在 CURLOPT_FOLLOWLOCATION开启时，使用的协议。默认允许除 FILE 和 SCP 外所有协议。这和 7.19.4 前的版本无条件支持所有支持的协议不同。关于协议常量，请参照CURLOPT_PROTOCOLS','curl_begin'=>'7.19.4','type'=>'integer'],
            'resume_from'=>['comment'=>'在恢复传输时，传递字节为单位的偏移量（用来断点续传）。','type'=>'integer'],
            'ssl_options'=>['comment'=>'','curl_begin'=>'7.25.0','php_begin'=>'7.0.7','type'=>'integer'],
            'ssl_verify-host'=>['comment'=>'设置为 1 是检查服务器SSL证书中是否存在一个公用名(common name)。译者注：公用名(Common Name)一般来讲就是填写你将要申请SSL证书的域名 (domain)或子域名(sub domain)。设置成 2，会检查公用名是否存在，并且是否与提供的主机名匹配。 0 为不检查名称。在生产环境中，这个值应该是 2（默认值）。','type'=>'integer'],
            'ssl-version'=>['comment'=>'CURL_SSLVERSION_DEFAULT (0), CURL_SSLVERSION_TLSv1 (1), CURL_SSLVERSION_SSLv2 (2), CURL_SSLVERSION_SSLv3 (3), CURL_SSLVERSION_TLSv1_0 (4), CURL_SSLVERSION_TLSv1_1 (5) ， CURL_SSLVERSION_TLSv1_2 (6) 中的其中一个。','type'=>'integer'],
            'stream_weight'=>['comment'=>'设置 stream weight 数值 ( 1 和 256 之间的数字).','curl_begin'=>'7.46.0','php_begin'=>'7.0.7','type'=>'integer'],
            'time-condition'=>['comment'=>'设置如何对待 CURLOPT_TIMEVALUE。使用 CURL_TIMECOND_IFMODSINCE，仅在页面 CURLOPT_TIMEVALUE 之后修改，才返回页面。没有修改则返回 "304 Not Modified" 头，假设设置了 CURLOPT_HEADER 为 TRUE。CURL_TIMECOND_IFUNMODSINCE则起相反的效果。默认为 CURL_TIMECOND_IFMODSINCE。','type'=>'integer'],
            'timeout'=>['comment'=>'允许 cURL 函数执行的最长秒数','type'=>'integer'],
            'timeout_ms'=>['comment'=>'设置cURL允许执行的最长毫秒数。如果 libcurl 编译时使用系统标准的名称解析器（ standard system name resolver），那部分的连接仍旧使用以秒计的超时解决方案，最小超时时间还是一秒钟。','curl_begin'=>'7.16.2','php_begin'=>'5.2.3','type'=>'integer'],
            'time-value'=>['comment'=>'秒数，从 1970年1月1日开始。这个时间会被 CURLOPT_TIMECONDITION使。默认使用CURL_TIMECOND_IFMODSINCE。','type'=>'integer'],
            'max_recv_speed_large'=>['comment'=>'如果下载速度超过了此速度(以每秒字节数来统计) ，即传输过程中累计的平均数，传输就会降速到这个参数的值。默认不限速。','curl_begin'=>'7.15.5','php_begin'=>'5.4.0','type'=>'integer'],
            'max_send_speed_large'=>['comment'=>'如果上传的速度超过了此速度(以每秒字节数来统计)，即传输过程中累计的平均数，传输就会降速到这个参数的值。默认不限速。','curl_begin'=>'7.15.5','php_begin'=>'5.4.0','type'=>'integer'],
            'ssh_auth_types'=>['comment'=>'A bitmask consisting of one or more of CURLSSH_AUTH_PUBLICKEY, CURLSSH_AUTH_PASSWORD, CURLSSH_AUTH_HOST, CURLSSH_AUTH_KEYBOARD. Set to CURLSSH_AUTH_ANY to let libcurl pick one.','curl_begin'=>'7.16.1','type'=>'integer'],
            'ip-resolve'=>['comment'=>'允许程序选择想要解析的 IP 地址类别。只有在地址有多种 ip 类别的时候才能用，可以的值有： CURL_IPRESOLVE_WHATEVER、 CURL_IPRESOLVE_V4、 CURL_IPRESOLVE_V6，默认是 CURL_IPRESOLVE_WHATEVER。','curl_begin'=>'7.10.8','type'=>'integer'],
            'ftp_file-method'=>['comment'=>'告诉 curl 使用哪种方式来获取 FTP(s) 服务器上的文件。可能的值有： CURLFTPMETHOD_MULTICWD、 CURLFTPMETHOD_NOCWD 和 CURLFTPMETHOD_SINGLECWD。','curl_begin'=>'7.15.1','php_begin'=>'5.3.0','type'=>'integer'],
            '__string',
            'ca-info'=>['comment'=>'一个保存着1个或多个用来让服务端验证的证书的文件名。这个参数仅仅在和CURLOPT_SSL_VERIFYPEER一起使用时才有意义。','type'=>'string'],
            'ca-path'=>['comment'=>' 一个保存着多个CA证书的目录。这个选项是和CURLOPT_SSL_VERIFYPEER一起使用的。','type'=>'string'],
            'cookie'=>['comment'=>'设定 HTTP 请求中"Cookie: "部分的内容。多个 cookie 用分号分隔，分号后带一个空格(例如， "fruit=apple; colour=red")。','type'=>'string'],
            'cookie-file'=>['comment'=>'包含 cookie 数据的文件名，cookie 文件的格式可以是 Netscape 格式，或者只是纯 HTTP 头部风格，存入文件。如果文件名是空的，不会加载 cookie，但 cookie 的处理仍旧启用。','type'=>'string'],
            'cookie-JAR'=>['comment'=>'连接结束后，比如，调用 curl_close 后，保存 cookie 信息的文件','type'=>'string'],
            'custom-request'=>['comment'=>'HTTP 请求时，使用自定义的 Method 来代替"GET"或"HEAD"。对 "DELETE" 或者其他更隐蔽的 HTTP 请求有用。有效值如 "GET"，"POST"，"CONNECT"等等；也就是说，不要在这里输入整行 HTTP 请求。例如输入"GET /index.html HTTP/1.0\r\n\r\n"是不正确的','type'=>'string'],
            'default_protocol'=>['comment'=>'URL不带协议的时候，使用的默认协议','curl_begin'=>'7.45.0','php_begin'=>'7.0.7','type'=>'string'],
            'dns_interface'=>['comment'=>'Set the name of the network interface that the DNS resolver should bind to.This must be an interface name (not an address).','curl_begin'=>'7.33.0','php_begin'=>'7.0.7','type'=>'string'],
            'dns_local_IP4'=>['comment'=>'Set the local IPv4 address that the resolver should bind to. The argumentshould contain a single numerical IPv4 address as a string.','curl_begin'=>'7.33.0','php_begin'=>'7.0.7','type'=>'string'],
            'dns_local_IP6'=>['comment'=>'Set the local IPv6 address that the resolver should bind to. The argumentshould contain a single numerical IPv6 address as a string.','curl_begin'=>'7.33.0','php_begin'=>'7.0.7','type'=>'string'],
            'egd-socket'=>['comment'=>'类似CURLOPT_RANDOM_FILE，除了一个Entropy Gathering Daemon套接字。','type'=>'string'],
            'ftp-port'=>['comment'=>'这个值将被用来获取供FTP"PORT"指令所需要的IP地址。 "PORT" 指令告诉远程服务器连接到我们指定的IP地址。这个字符串可以是纯文本的IP地址、主机名、一个网络接口名（UNIX下）或者只是一个"-"来使用默认的 IP 地址。','type'=>'string'],
            'encoding'=>['comment'=>'HTTP请求头中"Accept-Encoding: "的值。这使得能够解码响应的内容。支持的编码有"identity"，"deflate"和"gzip"。如果为空字符串""，会发送所有支持的编码类型','curl_begin'=>'7.10.0','type'=>'string'],
            'interface'=>['comment'=>'发送的网络接口（interface），可以是一个接口名、IP 地址或者是一个主机名。','type'=>'string'],
            'key-pass-wd'=>['comment'=>'使用 CURLOPT_SSLKEY 或 CURLOPT_SSH_PRIVATE_KEYFILE 私钥时候的密码','curl_begin'=>'7.16.1','type'=>'string'],
            'krb4-level'=>['comment'=>'KRB4 (Kerberos 4) 安全级别。下面的任何值都是有效的(从低到高的顺序)："clear"、"safe"、"confidential"、"private".。如果字符串以上这些，将使用"private"。这个选项设置为 NULL 时将禁用 KRB4 安全认证。目前 KRB4 安全认证只能用于 FTP 传输。','type'=>'string'],
            'login_options'=>['comment'=>'Can be used to set protocol specific login options, such as thepreferred authentication mechanism via "AUTH=NTLM" or "AUTH=*",and should be used in conjunction with the CURLOPT_USERNAME option.','curl_begin'=>'7.34.0','php_begin'=>'7.0.7','type'=>'string'],
            'pinned-public-key'=>['comment'=>'Set the pinned public key.The string can be the file name of your pinned public key. The fileformat expected is "PEM" or "DER". The string can also be anynumber of base64 encoded sha256 hashes preceded by "sha256//" andseparated by ";".','curl_begin'=>'7.39.0','php_begin'=>'7.0.7','type'=>'string'],
            'post-fields'=>['comment'=>'全部数据使用HTTP协议中的 "POST" 操作来发送。要发送文件，在文件名前面加上@前缀并使用完整路径。文件类型可在文件名后以 ";type=mimetype" 的格式指定。这个参数可以是 urlencoded 后的字符串，类似"para1=val1&para2=val2&..."，也可以使用一个以字段名为键值，字段数据为值的数组。如果value是一个数组，Content-Type头将会被设置成multipart/form-data。  从 PHP 5.2.0 开始，使用 @ 前缀传递文件时，value 必须是个数组。  从 PHP 5.5.0 开始, @ 前缀已被废弃，文件可通过 CURLFile 发送。设置 CURLOPT_SAFE_UPLOAD 为 TRUE 可禁用 @ 前缀发送文件，以增加安全性。','type'=>'string'],
            'private'=>['comment'=>'Any data that should be associated with this cURL handle.This datacan subsequently be retrieved with the CURLINFO_PRIVATE option of curl_getinfo(). cURL does nothing with this data.When using a cURL multi handle, this private data is typically aunique key to identify a standard cURL handle.','curl_begin'=>'7.10.3','type'=>'string'],
            'proxy'=>['comment'=>'HTTP 代理通道','type'=>'string'],
            'proxy_service_name'=>['comment'=>'代理验证服务的名称。','curl_begin'=>'7.34.0','php_begin'=>'7.0.7','type'=>'string'],
            'proxy-user-pwd'=>['comment'=>'一个用来连接到代理的"[username]:[password]"格式的字符串。','type'=>'string'],
            'random_file'=>['comment'=>'一个被用来生成 SSL 随机数种子的文件名。','type'=>'string'],
            'range'=>['comment'=>'以"X-Y"的形式，其中X和Y都是可选项获取数据的范围，以字节计。HTTP传输线程也支持几个这样的重复项中间用逗号分隔如"X-Y,N-M"。','type'=>'string'],
            'referer'=>['comment'=>'在HTTP请求头中"Referer: "的内容','type'=>'string'],
            'service_name'=>['comment'=>'验证服务的名称','curl_begin'=>'7.43.0','php_begin'=>'7.0.7','type'=>'string'],
            'ssh_host_public_key_md5'=>['comment'=>'包含 32 位长的 16 进制数值。这个字符串应该是远程主机公钥（public key） 的 MD5 校验值。在不匹配的时候 libcurl 会拒绝连接。此选项仅用于 SCP 和 SFTP 的传输','curl_begin'=>'7.17.1','type'=>'string'],
            'ssh_public_key-file'=>['comment'=>'','curl_begin'=>'7.16.1','type'=>'string'],
            'ssh_private_key-file'=>['comment'=>'','curl_begin'=>'7.16.1','type'=>'string'],
            'ssl_cipher_list'=>['comment'=>'一个SSL的加密算法列表。例如RC4-SHA和TLSv1都是可用的加密列表。','type'=>'string'],
            'ssl-cert'=>['comment'=>'一个包含 PEM 格式证书的文件名。','type'=>'string'],
            'ssl-cert-pass-wd'=>['comment'=>'使用CURLOPT_SSLCERT证书需要的密码','type'=>'string'],
            'ssl-cert-type'=>['comment'=>'证书的类型。支持的格式有"PEM" (默认值), "DER"和"ENG"。','curl_begin'=>'7.9.3','type'=>'string'],
            'ssl-engine'=>['comment'=>'用来在CURLOPT_SSLKEY中指定的SSL私钥的加密引擎变量。','type'=>'string'],
            'ssl-engine_default'=>['comment'=>'用来做非对称加密操作的变量','type'=>'string'],
            'ssl-key'=>['comment'=>'包含 SSL 私钥的文件名','type'=>'string'],
            'ssl-key-pass-wd'=>['comment'=>'在 CURLOPT_SSLKEY中指定了的SSL私钥的密码','type'=>'string'],
            'ssl-key-type'=>['comment'=>'CURLOPT_SSLKEY中规定的私钥的加密类型，支持的密钥类型为"PEM"(默认值)、"DER"和"ENG"。','type'=>'string'],
            'unix_socket_path'=>['comment'=>'使用 Unix 套接字作为连接，并用指定的 string 作为路径。','curl_begin'=>'7.40.0','php_begin'=>'7.0.7','type'=>'string'],
            'url'=>['comment'=>'需要获取的 URL 地址，也可以在curl_init() 初始化会话的时候。','type'=>'string'],
            'user-agent'=>['comment'=>'在HTTP请求中包含一个"User-Agent: "头的字符串。','type'=>'string'],
            //////////////
            'user-name'=>['comment'=>'','curl_begin'=>'7.19.1','php_begin'=>'5.5.0','type'=>'string'],
            'user-pwd'=>['comment'=>'传递一个连接中需要的用户名和密码，格式为："[username]:[','type'=>'string'],
            'x-oauth2_bearer'=>['comment'=>'指定 OAuth 2.0 access token','curl_begin'=>'7.33.0','php_begin'=>'7.0.7','type'=>'string'],
            '__array',
            'connect_to'=>['comment'=>'连接到指定的主机和端口，替换 URL 中的主机和端口。接受指定字符串格式的数组： HOST:PORT:CONNECT-TO-HOST:CONNECT-TO-PORT','curl_begin'=>'7.49.0','php_begin'=>'7.0.7','type'=>'array'],
            'http200-aliases'=>['comment'=>'HTTP 200 响应码数组，数组中的响应码被认为是正确的响应，而非错误','curl_begin'=>'7.10.3','type'=>'array'],
            'http-header'=>['comment'=>'设置 HTTP 头字段的数组。格式： array("Content-type: text/plain", "Content-length: 100")','type'=>'array'],
            'post-quote'=>['comment'=>'在 FTP 请求执行完成后，在服务器上执行的一组array格式的 FTP 命令。','type'=>'array'],
            'proxy-header'=>['comment'=>'传给代理的自定义 HTTP 头。','curl_begin'=>'7.37.0','php_begin'=>'7.0.7','type'=>'array'],
            'quote'=>['comment'=>'一组先于 FTP 请求的在服务器上执行的FTP命令。','type'=>'array'],
            'resolve'=>['comment'=>'提供自定义地址，指定了主机和端口。包含主机、端口和 ip 地址的字符串，组成 array 的，每个元素以冒号分隔。格式： array("example.com:80:127.0.0.1")','curl_begin'=>'7.21.3','php_begin'=>'5.5.0','type'=>'array'],
            '__source',
            'file'=>['comment'=>'设置输出文件，默认为STDOUT (浏览器)。','type'=>'source'],
            'infile'=>['comment'=>'上传文件时需要读取的文件。','type'=>'source'],
            'stderr'=>['comment'=>'错误输出的地址，取代默认的STDERR。','type'=>'source'],
            'write-header'=>['comment'=>'设置 header 部分内容的写入的文件地址。','type'=>'source'],
            '__function',
            'header-function'=>['comment'=>'设置一个回调函数，这个函数有两个参数，第一个是cURL的资源句柄，第二个是输出的 header 数据。header数据的输出必须依赖这个函数，返回已写入的数据大小。','type'=>'function'],
            'pass-wd-function'=>['comment'=>' 设置一个回调函数，有三个参数，第一个是cURL的资源句柄，第二个是一个密码提示符，第三个参数是密码长度允许的最大值。返回密码的值。','type'=>'function'],
            'progress-function'=>['comment'=>'设置一个回调函数，有五个参数，第一个是cURL的资源句柄，第二个是预计要下载的总字节（bytes）数。第三个是目前下载的字节数，第四个是预计传输中总上传字节数，第五个是目前上传的字节数。','type'=>'function'],
            'read-function'=>['comment'=>'回调函数名。该函数应接受三个参数。第一个是 cURL resource；第二个是通过选项 CURLOPT_INFILE 传给 cURL 的 stream resource；第三个参数是最大可以读取的数据的数量。回 调函数必须返回一个字符串，长度小于或等于请求的数据量（第三个参数）。一般从传入的 stream resource 读取。返回空字符串作为 EOF（文件结束） 信号','type'=>'function'],
            'write-function'=>['comment'=>'回调函数名。该函数应接受两个参数。第一个是 cURL resource；第二个是要写入的数据字符串。数 据必须在函数中被保存。函数必须准确返回写入数据的字节数，否则传输会被一个错误所中 断。','type'=>'function'],
            '__other',
            'share'=>['comment'=>'curl_share_init() 返回的结果。使 cURL 可以处理共享句柄里的数据。','type'=>'other']
        ];
    }


    /**
     * 获取版本信息 数组
     */
    private static function _version(){
        var_dump(curl_version());
    }

    /**
     * 检测list中的拼写是否和chm中的拼写完全一致
     *
     * chmList是直接从chm上复制下来的
     * @param $list
     */
    private static function _checkChm($list){
        $chmList = [ 'CURLOPT_AUTOREFERER','CURLOPT_BINARYTRANSFER','CURLOPT_COOKIESESSION','CURLOPT_CERTINFO','CURLOPT_CONNECT_ONLY','CURLOPT_CRLF','CURLOPT_DNS_USE_GLOBAL_CACHE','CURLOPT_FAILONERROR','CURLOPT_SSL_FALSESTART','CURLOPT_FILETIME','CURLOPT_FOLLOWLOCATION','CURLOPT_FORBID_REUSE','CURLOPT_FRESH_CONNECT','CURLOPT_FTP_USE_EPRT','CURLOPT_FTP_USE_EPSV','CURLOPT_FTP_CREATE_MISSING_DIRS','CURLOPT_FTPAPPEND','CURLOPT_TCP_NODELAY','CURLOPT_FTPASCII','CURLOPT_FTPLISTONLY','CURLOPT_HEADER','CURLINFO_HEADER_OUT','CURLOPT_HTTPGET','CURLOPT_HTTPPROXYTUNNEL','CURLOPT_MUTE','CURLOPT_NETRC','CURLOPT_NOBODY','CURLOPT_NOPROGRESS','CURLOPT_NOSIGNAL','CURLOPT_PATH_AS_IS','CURLOPT_PIPEWAIT','CURLOPT_POST','CURLOPT_PUT','CURLOPT_RETURNTRANSFER','CURLOPT_SAFE_UPLOAD','CURLOPT_SASL_IR','CURLOPT_SSL_ENABLE_ALPN','CURLOPT_SSL_ENABLE_NPN','CURLOPT_SSL_VERIFYPEER','CURLOPT_SSL_VERIFYSTATUS','CURLOPT_TCP_FASTOPEN','CURLOPT_TFTP_NO_OPTIONS','CURLOPT_TRANSFERTEXT','CURLOPT_UNRESTRICTED_AUTH','CURLOPT_UPLOAD','CURLOPT_VERBOSE','CURLOPT_BUFFERSIZE','CURLOPT_CLOSEPOLICY','CURLOPT_CONNECTTIMEOUT','CURLOPT_CONNECTTIMEOUT_MS','CURLOPT_DNS_CACHE_TIMEOUT','CURLOPT_EXPECT_100_TIMEOUT_MS','CURLOPT_FTPSSLAUTH','CURLOPT_HEADEROPT','CURLOPT_HTTP_VERSION','CURLOPT_HTTPAUTH','CURLOPT_INFILESIZE','CURLOPT_LOW_SPEED_LIMIT','CURLOPT_LOW_SPEED_TIME','CURLOPT_MAXCONNECTS','CURLOPT_MAXREDIRS','CURLOPT_PORT','CURLOPT_POSTREDIR','CURLOPT_PROTOCOLS','CURLOPT_PROXYAUTH','CURLOPT_PROXYPORT','CURLOPT_PROXYTYPE','CURLOPT_REDIR_PROTOCOLS','CURLOPT_RESUME_FROM','CURLOPT_SSL_OPTIONS','CURLOPT_SSL_VERIFYHOST','CURLOPT_SSLVERSION','CURLOPT_STREAM_WEIGHT','CURLOPT_TIMECONDITION','CURLOPT_TIMEOUT','CURLOPT_TIMEOUT_MS','CURLOPT_TIMEVALUE','CURLOPT_MAX_RECV_SPEED_LARGE','CURLOPT_MAX_SEND_SPEED_LARGE','CURLOPT_SSH_AUTH_TYPES','CURLOPT_IPRESOLVE','CURLOPT_FTP_FILEMETHOD','CURLOPT_CAINFO','CURLOPT_CAPATH','CURLOPT_COOKIE','CURLOPT_COOKIEFILE','CURLOPT_COOKIEJAR','CURLOPT_CUSTOMREQUEST','CURLOPT_DEFAULT_PROTOCOL','CURLOPT_DNS_INTERFACE','CURLOPT_DNS_LOCAL_IP4','CURLOPT_DNS_LOCAL_IP6','CURLOPT_EGDSOCKET','CURLOPT_ENCODING','CURLOPT_FTPPORT','CURLOPT_INTERFACE','CURLOPT_KEYPASSWD','CURLOPT_KRB4LEVEL','CURLOPT_LOGIN_OPTIONS','CURLOPT_PINNEDPUBLICKEY','CURLOPT_POSTFIELDS','CURLOPT_PRIVATE','CURLOPT_PROXY','CURLOPT_PROXY_SERVICE_NAME','CURLOPT_PROXYUSERPWD','CURLOPT_RANDOM_FILE','CURLOPT_RANGE','CURLOPT_REFERER','CURLOPT_SERVICE_NAME','CURLOPT_SSH_HOST_PUBLIC_KEY_MD5','CURLOPT_SSH_PUBLIC_KEYFILE','CURLOPT_SSH_PRIVATE_KEYFILE','CURLOPT_SSL_CIPHER_LIST','CURLOPT_SSLCERT','CURLOPT_SSLCERTPASSWD','CURLOPT_SSLCERTTYPE','CURLOPT_SSLENGINE','CURLOPT_SSLENGINE_DEFAULT','CURLOPT_SSLKEY','CURLOPT_SSLKEYPASSWD','CURLOPT_SSLKEYTYPE','CURLOPT_UNIX_SOCKET_PATH','CURLOPT_URL','CURLOPT_USERAGENT','CURLOPT_USERNAME','CURLOPT_USERPWD','CURLOPT_XOAUTH2_BEARER','CURLOPT_CONNECT_TO','CURLOPT_HTTP200ALIASES','CURLOPT_HTTPHEADER','CURLOPT_POSTQUOTE','CURLOPT_PROXYHEADER','CURLOPT_QUOTE','CURLOPT_RESOLVE','CURLOPT_FILE','CURLOPT_INFILE','CURLOPT_STDERR','CURLOPT_WRITEHEADER','CURLOPT_HEADERFUNCTION','CURLOPT_PASSWDFUNCTION','CURLOPT_PROGRESSFUNCTION','CURLOPT_READFUNCTION','CURLOPT_WRITEFUNCTION','CURLOPT_SHARE'];
        $emptyLine = 0;
        foreach ($list as $k => $kDetail){
            if(is_numeric($k)) {$emptyLine += 1;continue;}
            $constant = isset($kDetail['prefix'])?$kDetail['prefix']:'curlopt_';
            $constant .= strtr($k, ['-'=>'']);
            $constant = strtoupper($constant);
            if(!in_array($constant, $chmList)){
                echo $constant.PHP_EOL;
            }
        }

        echo count($list).'---'.count($chmList).'---empty_line:'.$emptyLine.PHP_EOL;
    }
    private static function printArrayToCode(array $array,$level = 0)
    {
        $str = "[";
        foreach ($array as $key => $value) {
            if(is_integer($key)){
                if(is_array($value)){
                    $str .= self::printArrayToCode($value, $level+1);
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
                    $str .= "'{$key}'=>".self::printArrayToCode($value, $level+1);
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
            $level == 1 and $str .= PHP_EOL;
        }
        $str = trim($str, ',');
        $str .= "]";
        return $str;
    }
    private static function dealErr($msg){
        throw new Exception($msg, 1);
    }
}