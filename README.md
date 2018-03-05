工具包合集
-

##### 1.Licenses tools help

#### 安装 (Installation):

    python setup.py install

#### 使用 (Usage):

1. 查看帮助 (Help command):
    
    python -m licepy -h

2. 创建证书 (Creating a Certificate):

    创建证书和私钥 (To Create a new Certificate **and** Private Key):
    
    python -m licepy cart certificate.pem CN=T2,O=T2cloud -newkey --issuer-key private-key.pem -
    
    创建证书指定私钥 (To Create a Certificate but use an *existing* Private Key):
    
    python -m licepy cart certificate.pem CN=T2,O=T2cloud  --issuer-key private-key.pem -
   
    
    
   
3. 申请licenses授权 (Apply for licenses):

    python -m licepy issue license.key not_before=2017-01-01T00:00:00,not_after=2026-01-01T00:00:00 --issuer-certificate certificate.pem --issuer-key private-key.pem - --license-file-password - --digest digest.txt

4. 查看licenses文件的授权信息 (Look at the license info):
    
    python -m licepy show license.key --issuer-certificate certificate.pem --license-file-password -
