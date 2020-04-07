# encoding: UTF-8

# Copyright 2015, Patrick Muench
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# author: Christoph Hartmann
# author: Dominik Richter
# author: Patrick Muench
# author: Mikhail Rusakovich

title 'NGINX server config'

# attributes
CLIENT_MAX_BODY_SIZE = attribute(
  'client_max_body_size',
  description: 'Sets the maximum allowed size of the client request body, specified in the “Content-Length” request header field. If the size in a request exceeds the configured value, the 413 (Request Entity Too Large) error is returned to the client. Please be aware that browsers cannot correctly display this error. Setting size to 0 disables checking of client request body size.',
  default: '1k'
)

CLIENT_BODY_BUFFER_SIZE = attribute(
  'client_body_buffer_size',
  description: 'Sets buffer size for reading client request body. In case the request body is larger than the buffer, the whole body or only its part is written to a temporary file. By default, buffer size is equal to two memory pages. This is 8K on x86, other 32-bit platforms, and x86-64. It is usually 16K on other 64-bit platforms.',
  default: '1k'
)

CLIENT_HEADER_BUFFER_SIZE = attribute(
  'client_header_buffer_size',
  description: 'Sets buffer size for reading client request header. For most requests, a buffer of 1K bytes is enough. However, if a request includes long cookies, or comes from a WAP client, it may not fit into 1K. If a request line or a request header field does not fit into this buffer then larger buffers, configured by the large_client_header_buffers directive, are allocated.',
  default: '1k'
)

LARGE_CLIENT_HEADER_BUFFER = attribute(
  'large_client_header_buffers',
  description: 'Sets the maximum number and size of buffers used for reading large client request header. A request line cannot exceed the size of one buffer, or the 414 (Request-URI Too Large) error is returned to the client. A request header field cannot exceed the size of one buffer as well, or the 400 (Bad Request) error is returned to the client. Buffers are allocated only on demand. By default, the buffer size is equal to 8K bytes. If after the end of request processing a connection is transitioned into the keep-alive state, these buffers are released.',
  default: '2 1k'
)

KEEPALIVE_TIMEOUT = attribute(
  'keepalive_timeout',
  description: 'The first parameter sets a timeout during which a keep-alive client connection will stay open on the server side. The zero value disables keep-alive client connections. The optional second parameter sets a value in the “Keep-Alive: timeout=time” response header field. Two parameters may differ.',
  default: '5 5'
)

CLIENT_BODY_TIMEOUT = attribute(
  'client_body_timeout',
  description: 'Defines a timeout for reading client request body. The timeout is set only for a period between two successive read operations, not for the transmission of the whole request body. If a client does not transmit anything within this time, the 408 (Request Time-out) error is returned to the client.',
  default: '10'
)

CLIENT_HEADER_TIMEOUT = attribute(
  'client_header_timeout',
  description: 'Defines a timeout for reading client request header. If a client does not transmit the entire header within this time, the 408 (Request Time-out) error is returned to the client.',
  default: '10'
)

SEND_TIMEOUT = attribute(
  'send_timeout',
  description: 'Sets a timeout for transmitting a response to the client. The timeout is set only between two successive write operations, not for the transmission of the whole response. If the client does not receive anything within this time, the connection is closed.',
  default: '10'
)

HTTP_METHODS = attribute(
  'http_methods',
  description: 'Specify the used HTTP methods',
  default: 'GET\|HEAD\|POST'
)

HTTP_METHODS_CHECK = attribute(
  'http_methods_check',
  description: 'Defines if http_methods should be checked in the nginx configuration',
  default: false
)

NGINX_COOKIE_FLAG_MODULE = attribute(
  'nginx_cookie_flag_module',
  description: 'Defines if nginx has been compiled with nginx_cookie_flag_module',
  default: false
)

only_if do
  command('nginx').exist?
end

# determine all required paths
nginx_path          = '/etc/nginx'
nginx_conf          = File.join(nginx_path, 'nginx.conf')
nginx_confd         = File.join(nginx_path, 'conf.d')
nginx_enabled       = File.join(nginx_path, 'sites-enabled')
nginx_parsed_config = command('nginx -T').stdout

nginx_static_path   = '/usr/share/nginx/html'

nginx_pid           = '/var/run/nginx.pid'

logrotate_path      = '/etc/logrotate.d'
nginx_logrotate_conf = File.join(logrotate_path, 'nginx')

options = {
  assignment_regex: /^\s*([^:]*?)\s*\ \s*(.*?)\s*;$/
}

options_add_header = {
  assignment_regex: /^\s*([^:]*?)\s*\ \s*(.*?)\s*;$/,
  multiple_values: true
}

control 'nginx-01' do
  impact 1.0
  title 'Running worker process as non-privileged user'
  desc 'The NGINX worker processes should run as non-privileged user. In case of compromise of the process, an attacker has full access to the system.'
  describe user(nginx_lib.valid_users) do
    it { should exist }
  end
  describe parse_config_file(nginx_conf, options) do
    its('user') { should eq nginx_lib.valid_users }
  end

  describe parse_config_file(nginx_conf, options) do
    its('group') { should_not eq 'root' }
  end
end

control 'nginx-02' do
  impact 1.0
  title 'Check NGINX config file owner, group and permissions.'
  desc 'The NGINX config file should owned by root, only be writable by owner and not write- and readable by others.'
  describe file(nginx_conf) do
    it { should be_owned_by 'root' }
    it { should be_grouped_into 'root' }
    it { should_not be_readable.by('others') }
    it { should_not be_writable.by('others') }
    it { should_not be_executable.by('others') }
  end
end

control 'nginx-03' do
  impact 1.0
  title 'Nginx default files'
  desc 'Remove the default nginx config files.'
  describe file(File.join(nginx_confd, 'default.conf')) do
    it { should_not be_file }
  end

  describe file(File.join(nginx_enabled, 'default')) do
    it { should_not be_file }
  end
end

control 'nginx-04' do
  impact 1.0
  title 'Check for multiple instances'
  desc 'Different instances of the nginx webserver should run in separate environments'
  describe command('ps aux | egrep "nginx: master" | egrep -v "grep" | wc -l') do
    its(:stdout) { should match(/^1$/) }
  end
end

control 'nginx-05' do
  impact 1.0
  title 'Disable server_tokens directive'
  desc 'Disables emitting nginx version in error messages and in the “Server” response header field.'
  describe parse_config(nginx_parsed_config, options) do
    its('server_tokens') { should eq 'off' }
  end
end

control 'nginx-06' do
  impact 1.0
  title 'Prevent buffer overflow attacks'
  desc 'Buffer overflow attacks are made possible by writing data to a buffer and exceeding that buffer boundary and overwriting memory fragments of a process. To prevent this in nginx we can set buffer size limitations for all clients.'
  describe parse_config(nginx_parsed_config, options) do
    its('client_body_buffer_size') { should eq CLIENT_BODY_BUFFER_SIZE }
  end
  describe parse_config(nginx_parsed_config, options) do
    its('client_max_body_size') { should eq CLIENT_MAX_BODY_SIZE }
  end
  describe parse_config(nginx_parsed_config, options) do
    its('client_header_buffer_size') { should eq CLIENT_HEADER_BUFFER_SIZE }
  end
  describe parse_config(nginx_parsed_config, options) do
    its('large_client_header_buffers') { should eq LARGE_CLIENT_HEADER_BUFFER }
  end
end

control 'nginx-07' do
  impact 1.0
  title 'Control simultaneous connections'
  desc 'NginxHttpLimitZone module to limit the number of simultaneous connections for the assigned session or as a special case, from one IP address.'
  describe parse_config(nginx_parsed_config, options) do
    its('limit_conn_zone') { should eq '$binary_remote_addr zone=default:10m' }
  end
  describe parse_config(nginx_parsed_config, options) do
    its('limit_conn') { should eq 'default 5' }
  end
end

control 'nginx-08' do
  impact 1.0
  title 'Prevent clickjacking'
  desc 'Do not allow the browser to render the page inside an frame or iframe.'
  describe parse_config(nginx_parsed_config, options_add_header) do
    its('add_header') { should include 'X-Frame-Options SAMEORIGIN' }
  end
end

control 'nginx-09' do
  impact 1.0
  title 'Enable Cross-site scripting filter'
  desc 'This header is used to configure the built in reflective XSS protection. This tells the browser to block the response if it detects an attack rather than sanitising the script.'
  describe parse_config(nginx_parsed_config, options_add_header) do
    its('add_header') { should include 'X-XSS-Protection "1; mode=block"' }
  end
end

control 'nginx-10' do
  impact 1.0
  title 'Disable content-type sniffing'
  desc 'It prevents browser from trying to mime-sniff the content-type of a response away from the one being declared by the server. It reduces exposure to drive-by downloads and the risks of user uploaded content that, with clever naming, could be treated as a different content-type, like an executable.'
  describe parse_config(nginx_parsed_config, options_add_header) do
    its('add_header') { should include 'X-Content-Type-Options nosniff' }
  end
end


control 'nginx-13' do
  impact 1.0
  title 'Add HSTS Header'
  desc 'HTTP Strict Transport Security (HSTS) is a web security policy mechanism which helps to protect websites against protocol downgrade attacks and cookie hijacking. It allows web servers to declare that web browsers (or other complying user agents) should only interact with it using secure HTTPS connections, and never via the insecure HTTP protocol. HSTS is an IETF standards track protocol and is specified in RFC 6797.'
  describe parse_config(nginx_parsed_config, options_add_header) do
    its('add_header') { should include 'Strict-Transport-Security max-age=15768000' }
  end
end

control 'nginx-14' do
  impact 1.0
  title 'Disable insecure HTTP-methods'
  desc 'Disable insecure HTTP-methods and allow only necessary methods.'
  ref 'OWASP HTTP Methods', url: 'https://www.owasp.org/index.php/Test_HTTP_Methods_(OTG-CONFIG-006)'

  only_if { HTTP_METHODS_CHECK != false }
  describe file(nginx_conf) do
    its('content') { should match(/^\s*if\s+\(\$request_method\s+\!\~\s+\^\(#{HTTP_METHODS}\)\$\)\{?$/) }
  end
end

control 'nginx-15' do
  impact 1.0
  title 'Content-Security-Policy'
  desc 'The Content-Security-Policy HTTP response header helps you reduce XSS risks on modern browsers by declaring what dynamic resources are allowed to load via a HTTP Header'
  describe parse_config(nginx_parsed_config, options_add_header) do
    its('add_header') { should include 'Content-Security-Policy "script-src \'self\'; object-src \'self\'"' }
  end
end

control 'nginx-16' do
  impact 1.0
  title 'Set cookie with HttpOnly and Secure flag'
  desc 'You can mitigate most of the common Cross Site Scripting attack using HttpOnly and Secure flag in a cookie. Without having HttpOnly and Secure, it is possible to steal or manipulate web application session and cookies and it’s dangerous.'
  only_if { NGINX_COOKIE_FLAG_MODULE != false }
  describe parse_config(nginx_parsed_config, options_add_header) do
    its('set_cookie_flag') { should include '* HttpOnly secure' }
  end
end

control 'nginx-17' do
  impact 1.0
  title 'Control timeouts to improve performance'
  desc 'Control timeouts to improve server performance and cut clients.'
  describe parse_config(nginx_parsed_config, options) do
    its('keepalive_timeout') { should eq KEEPALIVE_TIMEOUT }
  end
  describe parse_config(nginx_parsed_config, options) do
    its('client_body_timeout') { should eq CLIENT_BODY_TIMEOUT }
  end
  describe parse_config(nginx_parsed_config, options) do
    its('client_header_timeout') { should eq CLIENT_HEADER_TIMEOUT }
  end
  describe parse_config(nginx_parsed_config, options) do
    its('send_timeout') { should eq SEND_TIMEOUT }
  end
end

control 'cis-bench-2_1_2' do
  impact 1.0
  title 'Check for HTTP WebDAV module install'
  desc 'WebDAV functionality opens up an unnecessary path for exploiting your web server. Through misconfigurations of WebDAV operations, an attacker may be able to access and manipulate files on the server.'
  describe command('nginx -V 2>&1 | grep http_dav_module'), :sensitive do
    its(:stdout) { should be_empty }
  end
end

control 'cis-bench-2_1_3' do
  impact 1.0
  title 'Check modules with gzip functionality install'
  desc 'Compression has been linked with the Breach attack and others. While the Breach attack has been mitigated with modern usages of the HTTP protocol, disabling the use of compression is considered a defense-in-depth strategy to mitigate other attacks. '
  describe command('nginx -V 2>&1 | grep "http_gzip_module\|http_gzip_static_module"'), :sensitive do
    its(:stdout) { should be_empty }
  end
end

control 'cis-bench-2_1_4' do
  impact 1.0
  title 'Check autoindex module is disabled'
  desc 'Automated directory listings may reveal information helpful to an attacker, such as naming conventions and directory paths. Directory listings may also reveal files that were not intended to be revealed.'
  
  only_if{ command("egrep -i '^\s*autoindex\s+' #{nginx_conf}").stdout != '' }
  
  describe parse_config(nginx_parsed_config, options) do
	its('autoindex') { should eq 'off' }
  end
end

control 'cis-bench-2_2_2' do
  impact 1.0
  title 'Check Nginx Service account is locked'
  desc 'As a defense-in-depth measure, the nginx user account should be locked to prevent logins and to prevent someone from switching users to nginx using the password. In general, there shouldn\'t be a need for anyone to have to su as nginx, and when there is a need, sudo should be used instead, which would not require the nginx account password. '

  describe command('passwd -S nginx') do
    its(:stdout) { should match(/Password locked|nginx L/) }
  end
end

control 'cis-bench-2_2_3' do
  impact 1.0
  title 'Check NGINX service account has an invalid shell '
  desc 'The account used for nginx should only be used for the nginx service and does not need to have the ability to log in. This prevents an attacker who compromises the account to log in with it. '

  describe command('grep nginx /etc/passwd'), :sensitive do
      its(:stdout) { should include '/sbin/nologin' }
  end
end

control 'cis-bench-2_3_1' do
  impact 1.0
  title 'Check NGINX directories and files are owned by root'
  desc 'Setting ownership to only those users in the root group and the root user will reduce the likelihood of unauthorized modifications to the nginx configuration files.'
  describe file(nginx_path) do
    it { should be_owned_by 'root' }
  end
end

control 'cis-bench-2_3_2' do
  impact 1.0
  title 'Check access to NGINX directories and files is restricted'
  desc 'This ensures that only users who need access to configuration files are able to view them, thus preventing unauthorized access. Other users will need to use sudo in order to access these files.'
  describe file(nginx_path) do
    its('mode') { should cmp '0750' }
  end

  describe file(nginx_confd) do
     its('mode') { should cmp '0750' }
  end

   describe file(nginx_conf) do
      its('mode') { should cmp '0640' }
   end
end

control 'cis-bench-2_3_3' do
  impact 1.0
  title 'Check NGINX process ID (PID) file is secured'
  desc 'The PID file should be owned by root and the group root. It should also be readable to everyone, but only writable by root (permissions 644). This will prevent unauthorized modification of the PID file, which could cause a denial of service. '
  describe file("#{nginx_pid}") do
    its('mode') { should cmp '0644' }
  end
end

control 'cis-bench-2_3_4' do
  impact 1.0
  title 'Check the core dump directory is secured'
  desc 'Core dumps may contain sensitive information that should not be accessible by other accounts on the system. '

  only_if{ command("grep working_directory #{nginx_conf}").stdout != '' }

  working_dir_option = parse_config(nginx_parsed_config, options).params['working_directory']
  server_root_option = parse_config(nginx_parsed_config, options).params['root']

  describe file(working_dir_option) do
    its('path') { should_not include server_root_option }

    it { should be_owned_by 'root' }

    it { should_not be_readable.by('others') }
    it { should_not be_writable.by('others') }
    it { should_not be_executable.by('others') }
  end
end

control 'cis-bench-2_4_1' do
  impact 1.0
  title 'Check NGINX only listens for network connections on authorized ports'
  desc 'Limiting the listening ports to only those that are authorized helps to ensure no unauthorized services are running through the use of nginx.'
  command("grep -hir listen #{nginx_path}").stdout.split("\n").each do |listen_option|
      next if listen_option.strip.start_with?("#")

      describe command("echo #{listen_option}") do
        its(:stdout) { should match '^.+(\s|:)(80|443)(\s|;).*$' }
      end

  end
end

control 'cis-bench-2_4_2' do
  impact 1.0
  title 'Check requests for unknown host names are rejected'
  desc 'Whitelisting specific hosts and blocking access to all other hosts, you help to mitigate host header injection attacks against your server. Such attacks could be used by an attacker to redirect you to a rogue host and execute scripts or get you to input credentials.'

  protocols = ['http', 'https']

  protocols.each do |protocol|
      describe http("#{protocol}://127.0.0.1", headers: {'Host' => 'invalid.host.com'}) do
        its('status') { should cmp 404 }
      end
   end

end

control 'cis-bench-2_5_2' do
  impact 0.5
  title 'Check default error and index.html pages do not reference NGINX '
  desc 'By gathering information about the server, attackers can target attacks against its known vulnerabilities. Removing pages that disclose the server runs NGINX helps reduce targeted attacks on the server'

  disclose_files = ['index.html', '50x.html']

  disclose_files.each do |disclose_file|
    describe command("grep -i nginx #{nginx_static_path}/#{disclose_file}"), :sensitive do
        its(:stdout) { should be_empty }
    end
   end

end

control 'cis-bench-2_5_3' do
  impact 1.0
  title 'Check hidden file serving is disabled'
  desc 'Disabling hidden files prevents an attacker from being able to reference a hidden file that may be put in your location and have sensitive information, like .git files'

  describe command("grep location #{nginx_conf}") do
      its(:stdout) { should include('deny all').and include('return 404') }
  end
end

control 'cis-bench-2_5_4' do
  impact 1.0
  title 'Check NGINX reverse proxy does not enable information disclosure'
  desc 'Attackers can conduct reconnaissance on a website using these response headers, then target attacks for specific known vulnerabilities associated with the underlying technologies. Removing these headers will reduce the likelihood of targeted attacks.'

  describe command("grep proxy_hide_header #{nginx_conf}") do
      its(:stdout) { should include('X-Powered-By').and include('Server') }
  end
end

control 'cis-bench-3_1' do
  impact 0.5
  title 'Check detailed logging is enabled'
  desc 'Performing detailed logging ensures that incident responders, auditors, and others are able to clearly view the activity that has occurred on your server.'

  describe parse_config(nginx_parsed_config, options) do
 	its('log_format') { should_not be_nil }
  end
end

control 'cis-bench-3_2' do
  impact 1.0
  title 'Check access logging is enabled'
  desc 'Access logging allows incident responders and auditors to investigate access to a system in the event of an incident.'
  command("grep -hir access_log #{nginx_path}").stdout.split("\n").each do |access_log_option|
      next if access_log_option.strip.start_with?("#")

      describe command("echo #{access_log_option.strip}") do
        its(:stdout) { should_not match('(^.+\soff\s.*$)') }
      end
  end
end

control 'cis-bench-3_3' do
  impact 1.0
  title 'Check error logging is enabled and set to the info logging level'
  desc 'Error logging can be useful in identifying an attacker attempting to exploit a system and recreating an attackers steps. Error logging also helps with identifying possible issues with an application'

  describe parse_config(nginx_parsed_config, options) do
  	its('error_log') { should_not be_nil }
  end
end

control 'cis-bench-3_4' do
  impact 1.0
  title 'Check log files are rotated'
  desc 'Log files are important to track activity that occurs on your server, but they take up significant amounts of space. Log rotation should be configured in order to ensure the logs do not consume so much disk space that logging becomes unavailable.'

   describe command("cat #{nginx_logrotate_conf} | grep '\srotate\s'") do
      its(:stdout) { should_not be_empty }
   end

end

control 'cis-bench-3_5' do
  impact 1.0
  title 'Check error logs are sent to a remote syslog server'
  desc 'A centralized logging solution aggregates logs from multiple systems to ensure logs can be referenced in the event systems are thought to be compromised. Centralized log servers are also often used to correlate logs for potential patterns of attack. If a centralized logging solution is not used and systems (and their logs) are believed to be compromised, then logs may not be permitted to be used as evidence.'

  describe command("grep -hir syslog #{nginx_path}") do
    its(:stdout) { should_not be_empty }
  end
end

control 'cis-bench-3_7' do
  impact 1.0
  title 'Check proxies pass source IP information '
  desc 'Being able to identify the originating client IP address can help auditors or incident responders identify where the corresponding user came from. This may be useful in the event of an attack to analyze if the IP address is a good candidate for blocking. It may also be useful to correlate an attackers actions.'

  describe command("grep proxy_set_header #{nginx_conf}") do
      its(:stdout) { should include('X-Real-IP').and include('X-Forwarded-For') }
  end

  describe command("grep proxy_pass #{nginx_conf}") do
      its(:stdout) { should_not be_empty }
  end
end

control 'cis-bench-4_1' do
  impact 1.0
  title 'Check HTTP is redirected to HTTPS'
  desc 'Redirecting user agent traffic to HTTPS helps to ensure all user traffic is encrypted. Modern browsers alert users that your website is insecure when HTTPS is not used. This can decrease user trust in your website and ultimately result in decreased use of your web services. Redirection from HTTP to HTTPS couples security with usability; users are able to access your website even if they lack the security awareness to use HTTPS over HTTP when requesting your website.'

  describe command("grep -oPhr 'return\s+301\s+https:\/\/' #{nginx_path}") do
    its(:stdout) { should_not be_empty }
  end
end

control 'cis-bench-4_1_2' do
  impact 1.0
  title 'Check a trusted certificate and trust chain is installed'
  desc 'Without a certificate and full trust chain installed on your web server, modern browsers will flag your web server as untrusted.'

   describe command("grep -ir 'ssl_certificate\s' #{nginx_path}"), :sensitive do
     its(:stdout) { should_not be_empty }
   end

  describe.one do
      command("grep -hir 'ssl_certificate\s' #{nginx_path}").stdout.split("\n").each do |ssl_certificate_option|
         describe command("echo '#{ssl_certificate_option.strip}'"), :sensitive do
            its(:stdout) { should_not start_with("#") }
         end
      end
  end
end

control 'cis-bench-4_1_3' do
  impact 1.0
  title 'Check private key permissions are restricted'
  desc 'A servers private key file should be restricted to 400 permissions. This ensures only the owner of the private key file can access it. This is the minimum necessary permissions for the server to operate. If the private key file is not protected, an unauthorized user with access to the server may be able to find the private key file and use it to decrypt traffic sent to your server.'

  command("grep -irl ssl_certificate_key #{nginx_path}").stdout.split("\n").each do |ssl_key_option_config_path|
    ssl_key_path = parse_config(ssl_key_option_config_path, options).params['ssl_certificate_key']
    next if ssl_key_path.nil? || ssl_key_path.empty?

      describe file(ssl_key_path), :sensitive do
          its('mode') { should cmp '0400' }
      end
   end
end



