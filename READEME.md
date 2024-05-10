# win编译c文件
https://www.cygwin.com/install.html 下载cygwin
cwygin 安装gcc https://blog.csdn.net/B11050729/article/details/132279751

切换目录 win
cd /cygdrive/e/icron-icc-workspace


提示找不到jni.h和jni_md.h，原因是cygwin中的gcc工具包include缺少了jni的头文件
jni/jni.h文件放到cygwin的gcc/include 里cygwin64\lib\gcc\x86_64-pc-cygwin\11\include
[//]: # (        这俩文件的位置分别在，jdk的安装路径下：)

[//]: # (        %JAVA_HOME%/include/  和 %JAVA_HOME%/include/win32/)

[//]: # (        复制到“cygwin/gcc&#40;当前用到的版本&#41;/include/”下，即可解决问题)