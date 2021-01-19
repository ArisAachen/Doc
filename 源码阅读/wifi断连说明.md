#　背景说明
实际项目过程中，发现联想设备在工行项目中存在WiFi频繁断线的问题，需要深入研究其断开的原因。

## 调研过程
1. 实际情况是，实际已经连上WiFi，但是在数秒后，无线网络发生断连的现象。在实际查看wpa的日志中，发现已经完成了CTRL-EVENT-CONNECTED连接。详细可以查看wpa_20200108.log。
2. 连接上之后，发送断连的原因，从ｗpa上看，应该是wpa进行了重认证的操作，具体原因从wpa分析不出，因而需要取得dmseg内核日志分析。
3. 实际dmseg日志看到wlp6s0: deauthenticating应该是下线了认证信息。而后请求了新的bssid连接，应该是为了WiFi漫游。而此次认证一直失败。详细可以查看dmesg.log。

## 调研方向
1. 个别deauthenticating的日志原因输出了by local choice，查阅资料可能是由于管理network的工具冲突了。可以参照https://bbs.archlinux.org/viewtopic.php?id=233365，关闭多余的网络，紧产生配置文件，采用wpa_supplicant连接网络。
2. 重认证失败，有可能的原因是OPT密码在不同的ssid上的有效时间不同导致的。从ｗpa日志上可以看出实际上wpa已经在尝试做wifi漫游的操作。可以在连接的时候强制锁定bssid，这样可以禁止bgscan或者wifi漫游。方便分析是否是由于bscan或者wifi漫游引起的。为了防止2.4G无线的干扰，可以选择连接bssid为5G的网络，并指定NetworkManager的band字段为a，禁止2.4G的连接。

## 规避说明
实际上采用OPT的认证方式并不明智，OPT本质上是为了做密码有效性的校验。而802.1X在WiFi漫游的时候，会进行Pre-Authenticate，这时会用旧的密码进行验证，如果此时密码失效，可能就会导致WiFi漫游过程中频繁的验证失败。建议可以采用固定的WiFi密码+Portal验证方式。一方面可以保证WiFi漫游的时候密码校验不会失败。另一方面也可以保证密码有效性。