#!/bin/sh

ARCHIVE_UBUNTU=http://archive.ubuntu.com/ubuntu/
ARCHIVE_UBUNTU_CN=http://cn.archive.ubuntu.com/ubuntu/
ARCHIVE_NETEASE=http://mirrors.163.com/ubuntu/
ARCHIVE_SOHU=http://mirrors.sohu.com/ubuntu/
ARCHIVE_USTC=https://mirrors.ustc.edu.cn/ubuntu/
ARCHIVE_ALIYUN=http://mirrors.aliyun.com/ubuntu/

version=`lsb_release -sc`
echo "Current repo version is ${version}"

SOURE_LIST=/etc/apt/sources.list
DST_SOURE_LIST=$SOURE_LIST.backup

rm -rf $DST_SOURE_LIST

touch $SOURE_LIST
mv $SOURE_LIST $DST_SOURE_LIST

PICKED_ARCHIVE=$ARCHIVE_UBUNTU

echo 'Input your prefer sources within [ubuntu, ubuntu_cn, netease, sohu, aliyun, ustc], default [ubuntu]'
echo 'Your prefer is:\c'
read souce_Name

case $souce_Name in
    ubuntu)    echo 'ubuntu picked'
               PICKED_ARCHIVE=$ARCHIVE_UBUNTU 
    ;;
    ubuntu_cn) echo 'ubuntu_cn picked'
               PICKED_ARCHIVE=$ARCHIVE_UBUNTU_CN
    ;;
    netease)   echo 'netease picked'
               PICKED_ARCHIVE=$ARCHIVE_NETEASE
    ;;
    sohu)      echo 'sohu picked'
               PICKED_ARCHIVE=$ARCHIVE_SOHU
    ;;
    aliyun)    echo 'aliyun picked'
               PICKED_ARCHIVE=$ARCHIVE_ALIYUN
    ;;
    ustc)      echo 'ustc picked'
               PICKED_ARCHIVE=$ARCHIVE_USTC
    ;;
    "")        
               PICKED_ARCHIVE=$ARCHIVE_UBUNTU
    ;;
    *)         echo 'source name donot supported now'
               exit
    ;;
esac

echo 'Will you prefer to check the available package update?[Y, N], default [N]'
echo 'Your prefer is:\c'
read update_enable

PICKED_UPDATE=N
case $update_enable in
    y)  PICKED_UPDATE=Y 
    ;;
    Y)  PICKED_UPDATE=Y
    ;;
    n)  PICKED_UPDATE=N
    ;;
    N)  PICKED_UPDATE=N
    ;;
    "")   PICKED_UPDATE=N
    ;;
    *)  echo 'update enable err input'
        exit
    ;;
esac

echo 'Will you prefer to upgrade package?[Y, N], default [N]'
echo 'Your prefer is:\c'
read upgrade_enable

PICKED_UPGRADE=N
case $upgrade_enable in
    y)  PICKED_UPGRADE=Y 
    ;;
    Y)  PICKED_UPGRADE=Y
    ;;
    n)  PICKED_UPGRADE=N
    ;;
    N)  PICKED_UPGRADE=N
    ;;
    "") PICKED_UPGRADE=N
    ;;
    *)  echo 'update upgrade err input'
        exit
    ;;
esac

echo "deb $PICKED_ARCHIVE $version main restricted universe multiverse" >> $SOURE_LIST

deb_list="security updates proposed backports"
for i in $deb_list; do
    echo "deb $PICKED_ARCHIVE $version-$i main restricted universe multiverse" >> $SOURE_LIST
done

echo "deb-src $PICKED_ARCHIVE bionic main restricted universe multiverse" >> $SOURE_LIST

deb_list="security updates proposed backports"
for i in $deb_list; do
    echo "deb-src $PICKED_ARCHIVE $version-$i main restricted universe multiverse" >> $SOURE_LIST
done

if [ $PICKED_UPDATE = 'Y' ]; then
    echo "prepare to update"
    apt update -y
fi

if [ $PICKED_UPGRADE = 'Y' ]; then
    echo "prepare to upgrade"
    apt upgrade -y
fi
