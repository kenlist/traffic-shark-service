## 1.TrafficShark功能介绍

---

TrafficShark是基于 **Facebook/atc** 改造后的弱网模拟和抓包工具，可以快速进行弱网配置生成和对指定设备设置，同时还能实时抓包，查看设备上的传输详细信息。

```
TrafficShark项目是开源的，目标是希望大家能基于TrafficShark根据各自业务场景做定制，下一篇会介绍项目设计。
```

整体设备关系如下图，在树莓派通过lan0端口连接外网，wan0端口建立AP，并且在lan0和wan0之间建立包转发规则。测试设备通过连接AP接入网络，PC设备可以通过局域网直接访问树莓派的8080端口，打开TrafficShark控制面板进行控制。

![screenshot.png](http://ata2-img.cn-hangzhou.img-pub.aliyun-inc.com/ae6559aa9be311db6124984e38426c3b.png)

TrafficShark主界面由2部分组成：

1. Machine Settings - 测试设备管理和配置
2. Network Profiles - 弱网配置管理

![screenshot.png](http://ata2-img.cn-hangzhou.img-pub.aliyun-inc.com/e690eddd85104ca81e67b6637fa49739.png)

### 1.1 Network Profiles

---

网络配置管理可以创建、编辑、删除相关配置，目前网络配置能力与 **Facebook/atc** 的一致，可以设置Bandwidth、Latency、Loss、Corruption、Reorder等，保存后即可在主页看到相应配置。

![screenshot.png](http://ata2-img.cn-hangzhou.img-pub.aliyun-inc.com/16f8ebf747baa83c56757039eaf730e2.png)

对已被使用的网络配置进行编辑、删除，则会弹出相应提示，确认后会立即生效到各个使用设备上。

![screenshot.png](http://ata2-img.cn-hangzhou.img-pub.aliyun-inc.com/45f86fd68d9501a76b6ca5502da143b0.png)![](/assets/media/2017/05/02/trafficshark-tool-for-network-4.png)

### 1.2 Machine Settings

---

设备管理页面会自动扫描并列出当前已经连入AP的设备MAC和IP，之前有扫描过的但是当前没有在线的设备会显灰，如果超过2天都没有出现，则直接删除。

![screenshot.png](http://ata2-img.cn-hangzhou.img-pub.aliyun-inc.com/cee23665a2999f84a92fee07759722cc.png)

设备控制功能：

1. Profile - 可以为设备选择已保存的网络配置
2. Turn On - 把当前设备的网络配置启用，立即对设备的网络环境进行限制
3. Update - 把当前设备的网络配置选择保存下来，如果已经Turn On则立马生效到设备网络环境中
4. Capture - 打开该设备的抓包管理页面(Capture Panel)

### 1.3 Capture Panel

---

抓包管理页面主要提供以下功能：

1. 设置抓包过滤器(filter)
2. 开启抓包
3. General页 - 实时显示设备上下行流量
4. Detail页 - 实时显示设备抓到的包
5. 导出pcap文件

![screenshot.png](http://ata2-img.cn-hangzhou.img-pub.aliyun-inc.com/9600f2fdc22746fdca8aebabd9e9a556.png)

输入自定义filter后（如不输入则抓当前设备所有包），点击 Start Capture，则可以看到当前设备实时流量情况：

![screenshot.png](http://ata2-img.cn-hangzhou.img-pub.aliyun-inc.com/ef4362f65717c600c9f19ff478141c9b.png)

切换到Detail页面，则可以看到详细的包信息：

![screenshot.png](http://ata2-img.cn-hangzhou.img-pub.aliyun-inc.com/2d0dc2da13d27b3e662da13d30698a31.png)

每行包数据分别是时间(到毫秒)、源IP、目标IP、包大小、包层类型，点击每个item，还能展开查看每个包的每层包数据：

![screenshot.png](http://ata2-img.cn-hangzhou.img-pub.aliyun-inc.com/9f8f27c2cd5537e41bf81f32191b0ea2.png)

点击Export pcap，能立即把当前抓包情况通过pcap文件下载，下载后的文件可通过wireshark等其它抓包分析工具打开：

![screenshot.png](http://ata2-img.cn-hangzhou.img-pub.aliyun-inc.com/e26ca4791c4c125104eed845706064ab.png)

## 2. TrafficShark环境搭建与安装

---

### 2.1 环境

---

* **硬件**
  1. 树莓派3代（板载WiFi），这是我购买的[店铺](https://item.taobao.com/item.htm?spm=a1z09.2.0.0.lzcDi6&id=527525039334&_u=41tom485b0d)（不是卖广告）
  2. 连到外网的路由器（随意，我用的是cisco），树莓派与路由器通过网线连接
  3. Macbook Pro 2012款
  4. 测试手机若干
* **软件**
  1. 树莓派3代系统 - Linux raspberrypi 4.4.50-v7+
  2. OS X 10.11.6
  
下面开始在Mac中ssh到树莓派上进行环境配置。
  
### 2.2 WiFi热点搭建

---

> 参考文章：
> [USING YOUR NEW RASPBERRY PI 3 AS A WIFI ACCESS POINT WITH HOSTAPD](https://frillip.com/using-your-raspberry-pi-3-as-a-wifi-access-point-with-hostapd/)

#### 2.2.1 安装dnsmasq和hostapd

*在使用apt-get之前，先更新一下源，推荐使用aliyun的，可以上网找相关文章*

```
sudo apt-get install dnsmasq hostapd
```

#### 2.2.2 配置hostapd与wlan0接口


``` sudo vim /etc/dhcpcd.conf ```末尾添加：

``` 
denyinterfaces wlan0 
```

``` sudo vim /etc/network/interfaces ``` 对wlan0接口重新编辑：

```
allow-hotplug wlan0  
iface wlan0 inet static  
    address 172.24.1.1
    netmask 255.255.255.0
    network 172.24.1.0
    broadcast 172.24.1.255
```

``` sudo vim /etc/hostapd/hostapd.conf ``` 添加如下内容：

```
interface=wlan0
driver=nl80211
ssid=Pi3-AP
hw_mode=g
channel=6
ieee80211n=1
wmm_enabled=1
ht_capab=[HT40][SHORT-GI-20][DSSS_CCK-40]
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
wpa=2
wpa_key_mgmt=WPA-PSK
wpa_passphrase=raspberry
rsn_pairwise=CCMP
```

#### 2.2.3 配置dnsmasq

``` sudo vim /etc/dnsmasq.conf ``` 添加如下内容：

```
interface=wlan0
listen-address=172.24.1.1
bind-interfaces
server=8.8.8.8
domain-needed
bogus-priv
dhcp-range=172.24.1.50,172.24.1.150,12h
```

#### 2.2.4 配置包转发规则

``` sudo vim /etc/rc.local ```在exit 0之前添加如下内容：

```
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
iptables -A FORWARD -i eth0 -o wlan0 -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -A FORWARD -i wlan0 -o eth0 -j ACCEPT
```

#### 2.2.5 配置生效并启动AP

```sudo reboot```重启，让配置生效
```sudo hostapd /etc/hostapd/hostapd.conf```启动AP，成功后可看到：

![screenshot.png](http://ata2-img.cn-hangzhou.img-pub.aliyun-inc.com/3732e2cba1cd624c144a082f6316f8e0.png)

### 2.3 编译并运行TrafficShark

---

#### 2.3.1 依赖工具和环境安装

1. 安装git
2. 安装python
3. 安装pip

参考命令： ``` sudo apt-get install git python python-pip ```

#### 2.3.2 TrafficSharkService安装与运行

TrafficSharkService是TrafficShark的后台管理进程服务

``` 
pi@raspberrypi:~ $ git clone git@gitlab.alibaba-inc.com:traffic-shark/traffic-shark-service.git 
pi@raspberrypi:~/traffic-shark-service $ sudo ./install.sh
pi@raspberrypi:~/traffic-shark-service $ sudo ./run.sh
```

运行成功后应如下：

![screenshot.png](http://ata2-img.cn-hangzhou.img-pub.aliyun-inc.com/6b6ae865e6d043388ad17b9ecf164e4d.png)

#### 2.3.3 TrafficSharkConsole安装与运行

TrafficSharkConsole是TrafficShark的前台控制面板

``` 
pi@raspberrypi:~ $ git clone git@gitlab.alibaba-inc.com:traffic-shark/traffic-shark-console.git
pi@raspberrypi:~/traffic-shark-console $ sudo ./install.sh
pi@raspberrypi:~/traffic-shark-console $ sudo ./run.sh
```

运成功后应如下：

![screenshot.png](http://ata2-img.cn-hangzhou.img-pub.aliyun-inc.com/b72447834c58f025e211b12daf792ba6.png)

在PC中直接通过浏览器访问{树莓派ip}:8080地址即可看到：

![screenshot.png](http://ata2-img.cn-hangzhou.img-pub.aliyun-inc.com/4a431c68e0f33199bb3953fb4b8c8914.png)

