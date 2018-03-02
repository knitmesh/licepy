工具包合集
-

##### 1.Licenses tools help

#### 安装:

    python setup.py install

#### 使用:

1. 查看帮助
    
    python -m licepy -h

2. 创建证书:

    创建证书和私钥:
    
    python -m licepy cart certificate.pem CN=T2,O=T2cloud -newkey --issuer-key private-key.pem -
    
    创建证书指定私钥:
    
    python -m licepy cart certificate.pem CN=T2,O=T2cloud  --issuer-key private-key.pem -
   
    
    
   
3. 申请licenses授权:

    python -m licepy issue license.key not_before=2017-01-01T00:00:00,not_after=2026-01-01T00:00:00 --issuer-certificate certificate.pem --issuer-key private-key.pem - --license-file-password - --digest digest.txt

4. 查看licenses文件的授权信息:
    
    python -m licepy show license.key --issuer-certificate certificate.pem --license-file-password -