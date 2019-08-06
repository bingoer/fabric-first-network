#!/bin/bash
#
# Copyright IBM Corp All Rights Reserved
#
# SPDX-License-Identifier: Apache-2.0

set -e
# SDIR=$(dirname "$0")

# ordererCA 的 URL
URLorderer=localhost:7054
# org1CA 的 URL
URLorg1=localhost:7055
# org2CA 的 URL
URLorg2=localhost:7056
# tlsCA 的 URL
URLtls=localhost:7057
# tlsorg1CA 的 URL
URLtlsorg1=localhost:7058
# tlsorg2CA 的 URL
URLtlsorg2=localhost:7059

# scripts 目录上一级目录
SDIR=$(
	cd ../"$(dirname "$0")"
	pwd
)

# 生成的ca的文件的相对根目录
CA_DIR=$SDIR/fabric-ca-files
ORDERER_DIR=$SDIR/crypto-config/ordererOrganizations
PEER_DIR=$SDIR/crypto-config/peerOrganizations


# Copy the org's admin cert into some target MSP directory
# This is only required if ADMINCERTS is enabled.
function copyAdminCert() {
	if [ $# -ne 3 ]; then
		fatal "Usage: copyAdminCert <adminCertDir> <targetMSPDIR>"
	fi
	if $ADMINCERTS; then
		dstDir=$2/admincerts
		mkdir -p $dstDir
		cp $1/signcerts/* $dstDir/$3
	fi
}

function copyServerTls() {
	if [ $# -ne 1 ]; then
		fatal "Usage: copyTls <targetMSPDIR>"
	fi
	cp $1/keystore/* $1/server.key
	cp $1/signcerts/* $1/server.crt
	cp $1/tlscacerts/* $1/ca.crt
}

function copyClientTls() {
	if [ $# -ne 1 ]; then
		fatal "Usage: copyTls <targetMSPDIR>"
	fi
	cp $1/keystore/* $1/client.key
	cp $1/signcerts/* $1/client.crt
	cp $1/tlscacerts/* $1/ca.crt
}

function copytlsCaCerts(){
	if [ $# -ne 3 ]; then
		fatal "Usage: copyAdminCert <tlscaCertDir> <targetMSPDIR>"
	fi
	if $ADMINCERTS; then
		dstDir=$2/tlscacerts
		mkdir -p $dstDir
		cp $1/tlscacerts/* $dstDir/$3
	fi
}

function rmMSP(){
	# 删除 example.com/msp 下不必要文件
	if [ $2 == 1 ]; then
		rm $1/keystore $1/signcerts $1/user $1/IssuerPublicKey $1/IssuerRevocationPublicKey -rf
	fi

	# 删除 example.com/users,orderers/msp 下不必要文件
	if [ $2 == 2 ]; then
		rm $1/user $1/IssuerPublicKey $1/IssuerRevocationPublicKey -rf
	fi

}

function rmTLS(){
	rm $1/cacerts $1/keystore $1/signcerts $1/tlscacerts $1/user $1/IssuerPublicKey $1/IssuerRevocationPublicKey -rf
}

function reName(){
	if [ $# -ne 3 ]; then
		fatal "Usage: copyAdminCert <tlscaCertDir> <targetMSPDIR>"
	fi
	
	if [ $3 == 1 ]; then
		mv $1/cacerts/* $1/cacerts/$2
	fi

	if [ $3 == 2 ]; then
		mv $1/cacerts/* $1/cacerts/$2
		mv $1/signcerts/* $1/signcerts/$2
	fi
}

function touchConfig(){
	for ((i = 1; i<= 2; i++)) do
		org=org$i

		touch $PEER_DIR/$org.example.com/msp/config.yaml	

		echo "NodeOUs:"&>$PEER_DIR/$org.example.com/msp/config.yaml
		echo "  Enable: true"&>>$PEER_DIR/$org.example.com/msp/config.yaml
		echo "  ClientOUIdentifier:"&>>$PEER_DIR/$org.example.com/msp/config.yaml
		echo "    Certificate: cacerts/ca.$org.example.com-cert.pem"&>>$PEER_DIR/$org.example.com/msp/config.yaml
		echo "    OrganizationalUnitIdentifier: client"&>>$PEER_DIR/$org.example.com/msp/config.yaml
		echo "  PeerOUIdentifier:"&>>$PEER_DIR/$org.example.com/msp/config.yaml
		echo "    Certificate: cacerts/ca.$org.example.com-cert.pem"&>>$PEER_DIR/$org.example.com/msp/config.yaml
		echo "    OrganizationalUnitIdentifier: peer"&>>$PEER_DIR/$org.example.com/msp/config.yaml
		
		cp $PEER_DIR/$org.example.com/msp/config.yaml $PEER_DIR/$org.example.com/peers/peer0.$org.example.com/msp/config.yaml
		cp $PEER_DIR/$org.example.com/msp/config.yaml $PEER_DIR/$org.example.com/peers/peer1.$org.example.com/msp/config.yaml
	done
}


function addOrg() {
	echo "==============Add orgs======="
	fabric-ca-client affiliation list
	fabric-ca-client affiliation remove --force org1
	fabric-ca-client affiliation remove --force org2

	fabric-ca-client affiliation add com
	fabric-ca-client affiliation add com.example
	fabric-ca-client affiliation add com.example.org1
	fabric-ca-client affiliation add com.example.org2
}

# 生成 Orderer 节点的 msp 证书文件 [ca.example.com 7054]
function generateOrdererMSP() {

	echo "==============init-ordererCA-Admin====START==="
	# 登记 OrdererCA 管理员身份
	export FABRIC_CA_CLIENT_HOME=$CA_DIR/orderercaAdmin
	fabric-ca-client enroll -d -u http://admin:adminpw@$URLorderer --csr.cn Admin@example.com  --csr.hosts Admin@example.com
	echo "==============init-ordererCA-Admin====END==="

	addOrg # 创建联盟

	echo "==============orderer-Register====START==="
	#注册 orderer.example.com 身份实体
	#sleep 1
	fabric-ca-client register -d -u http://admin:adminpw@$URLorderer --id.secret orderer.example.compw --id.name orderer.example.com --id.type orderer --id.affiliation com.example
	echo "==============orderer-Register====END==="	
	
	echo "==============orderer-enroll====START==="
	# 登记 orderer.example.com 身份实体，生成 msp 证书文件
	fabric-ca-client enroll -d -u http://orderer.example.com:orderer.example.compw@$URLorderer --csr.cn orderer.example.com  --csr.hosts orderer.example.com -M $ORDERER_DIR/example.com/orderers/orderer.example.com/msp --id.affiliation com.example
	echo "==============orderer-enroll====END==="
	
	echo "==============orderer-getcacert====START==="
	#获取服务端 CA 证书文件并保存到 msp 目录下的 cacerts(根CA) 和 intermediatecerts(中间CA) 文件中
	fabric-ca-client getcacert -d -u http://$URLorderer -M $ORDERER_DIR/example.com/msp --id.type client --id.affiliation com.example
	echo "==============orderer-getcacert====END==="

	echo "==============orderer-Register-Admin====START==="
	#注册 orderer 管理员 admin 用户身份实体
	# fabric-ca-client register -d --id.secret Admin.example.compw --id.name Admin@example.com --id.type client --id.affiliation com.example --id.attrs '"hf.Registrar.Roles=client,orderer,peer,user","hf.Registrar.DelegateRoles=client,orderer,peer,user",hf.Registrar.Attributes=*,hf.GenCRL=true,hf.Revoker=true,hf.AffiliationMgr=true,hf.IntermediateCA=true,role=admin:ecert'
	fabric-ca-client register -d -u http://admin:adminpw@$URLorderer --id.secret Admin.example.compw --id.name Admin@example.com --id.type client --id.affiliation com.example --id.attrs admin=true:ecert
	echo "==============orderer-Register-Admin====END==="	
	
	echo "==============orderer-enroll-Admin====START==="
	#登记管理员用户，生成管理员用户证书
	export FABRIC_CA_CLIENT_HOME=$ORDERER_DIR/example.com/users/Admin@example.com
	fabric-ca-client enroll -d -u http://Admin@example.com:Admin.example.compw@$URLorderer --csr.cn Admin@example.com  --csr.hosts Admin@example.com --id.affiliation com.example
	rm $ORDERER_DIR/example.com/users/Admin@example.com/fabric-ca-client-config.yaml
	echo "==============orderer-enroll-Admin====END==="	
	
	# cp $$ORDERER_DIR/example.com/admin/msp/signcerts/* $$ORDERER_DIR/example.com/msp/admincerts/cert.pem
	# 将管理员用户证书拷贝到 本组织 每个实体 msp 目录下的 admincerts 目录中
	echo "==============orderer-copy-admincerts====START==="
	# Orderer 节点 msp 下的 admincerts
	copyAdminCert $ORDERER_DIR/example.com/users/Admin@example.com/msp $ORDERER_DIR/example.com/msp Admin@example.com-cert.pem
	# Orderer 节点下 users/Admin@example.com 的 admincerts
	copyAdminCert $ORDERER_DIR/example.com/users/Admin@example.com/msp $ORDERER_DIR/example.com/users/Admin@example.com/msp Admin@example.com-cert.pem
	# Orderer 节点下 orderers/orderer.example.com 的 admincerts
	copyAdminCert $ORDERER_DIR/example.com/users/Admin@example.com/msp $ORDERER_DIR/example.com/orderers/orderer.example.com/msp Admin@example.com-cert.pem
	echo "==============orderer-copy-admincerts====END==="
	
	echo "==============orderer-rm-msp-unimportant-file====START==="
	rmMSP $ORDERER_DIR/example.com/msp 1

	rmMSP $ORDERER_DIR/example.com/orderers/orderer.example.com/msp 2
	rmMSP $ORDERER_DIR/example.com/users/Admin@example.com/msp 2
	echo "==============orderer-rm-msp-unimportant-file====END==="
	
	echo "==============orderer-rename-msp-some-file====START==="
	mv $ORDERER_DIR/example.com/msp/cacerts/*  $ORDERER_DIR/example.com/msp/cacerts/ca.example.com-cert.pem 	
	mv $ORDERER_DIR/example.com/orderers/orderer.example.com/msp/cacerts/* $ORDERER_DIR/example.com/orderers/orderer.example.com/msp/cacerts/ca.example.com-cert.pem 
	mv $ORDERER_DIR/example.com/orderers/orderer.example.com/msp/signcerts/* $ORDERER_DIR/example.com/orderers/orderer.example.com/msp/signcerts/orderer.example.com-cert.pem
	mv $ORDERER_DIR/example.com/users/Admin@example.com/msp/cacerts/* $ORDERER_DIR/example.com/users/Admin@example.com/msp/cacerts/ca.example.com-cert.pem
	mv $ORDERER_DIR/example.com/users/Admin@example.com/msp/signcerts/* $ORDERER_DIR/example.com/users/Admin@example.com/msp/signcerts/Admin@example.com-cert.pem
	echo "==============orderer-rm-msp-unimportant-file====END==="
}

# 生成 orderer 下 orderer.example.com 和 Admin@example.com 中的 tls 证书 [tlsca.example.com 7057]
function generateOrdererTLS() {
	
	echo "==============init-tlsCA-Admin====START==="
	# 登记 tlsCA 管理员身份
	export FABRIC_CA_CLIENT_HOME=$CA_DIR/tlscaAdmin
	fabric-ca-client enroll -d -u http://admin:adminpw@$URLtls --csr.cn Admin@tlsca.example.com  --csr.hosts Admin@tlsca.example.com
	echo "==============init-tlsCA-Admin====END==="
	
	addOrg # 创建联盟
	
	echo "==============orderer-tls-Register====START==="
	# 在 tlsca 上注册 orderer.example.com 和 Admin@example.com 身份实体
	fabric-ca-client register -d -u http://admin:adminpw@$URLtls --id.secret orderer.example.compw --id.name orderer.example.com --id.affiliation com.example
	fabric-ca-client register -d -u http://admin:adminpw@$URLtls --id.secret Admin@example.compw --id.name Admin@example.com --id.affiliation com.example
	echo "==============orderer-tls-Register====END==="	
	
	echo "==============orderer-tls-enroll====START==="
	# 在 tlsca 上登记 orderer.example.com 和 Admin@example.com  身份实体，生成 tls 证书文件
	fabric-ca-client enroll -d --enrollment.profile tls -u http://orderer.example.com:orderer.example.compw@$URLtls -M $ORDERER_DIR/example.com/orderers/orderer.example.com/tls --csr.cn=orderer.example.com --csr.hosts=orderer.example.com --csr.hosts=orderer --id.affiliation com.example
	fabric-ca-client enroll -d --enrollment.profile tls -u http://Admin@example.com:Admin@example.compw@$URLtls -M $ORDERER_DIR/example.com/users/Admin@example.com/tls --id.affiliation com.example
	echo "==============orderer-tls-enroll====END==="

	echo "==============orderer-copy-tlscacerts====START==="
	# example.com/msp/tlscacerts
	copytlsCaCerts $ORDERER_DIR/example.com/orderers/orderer.example.com/tls $ORDERER_DIR/example.com/msp tlsca.example.com-cert.pem
	# example.com/orderers/orderer.example.com/msp/tlscacerts
	copytlsCaCerts $ORDERER_DIR/example.com/orderers/orderer.example.com/tls $ORDERER_DIR/example.com/orderers/orderer.example.com/msp tlsca.example.com-cert.pem
	# example.com/users/Admin@example.com/msp/tlscacerts
	copytlsCaCerts $ORDERER_DIR/example.com/orderers/orderer.example.com/tls $ORDERER_DIR/example.com/users/Admin@example.com/msp tlsca.example.com-cert.pem
	echo "==============orderer-copy-tlscacerts====END==="

	# cp $$ORDERER_DIR/example.com/orderer/tls/keystore/* $$ORDERER_DIR/example.com/orderer/tls/server.key
	# cp $$ORDERER_DIR/example.com/orderer/tls/signcerts/* $$ORDERER_DIR/example.com/orderer/tls/server.crt
	# cp $$ORDERER_DIR/example.com/orderer/tls/tlscacerts/* $$ORDERER_DIR/example.com/orderer/tls/ca.crt
	copyServerTls $ORDERER_DIR/example.com/orderers/orderer.example.com/tls

	copyClientTls $ORDERER_DIR/example.com/users/Admin@example.com/tls

	echo "==============orderer-rm-tls-unimportant-file====START==="
	rmTLS $ORDERER_DIR/example.com/orderers/orderer.example.com/tls
	rmTLS $ORDERER_DIR/example.com/users/Admin@example.com/tls
	echo "==============orderer-rm-tls-unimportant-file====END==="
}


# 生成 组织1 下的 pee0,pee1 相关的 msp 证书文件[ca.org1.example.com 7055],[ca.org2.example.com 7056]
function generateOrgMSP() {

	for ((i = 1; i <= 2; i++)) do
		org=org$i
		eval URLorg="$"URL$org

		echo "==============init-$orgCA-Admin====START==="
		# 登记 $orgCA 管理员身份
		export FABRIC_CA_CLIENT_HOME=$CA_DIR/${org}caAdmin
		fabric-ca-client enroll -d -u http://admin:adminpw@$URLorg --csr.cn Admin@$org.example.com  --csr.hosts Admin@$org.example.com
		echo "==============init-$orgCA-Admin====END==="
		
		addOrg # 创建联盟
	
		echo "============peer0,peer1-$org-Register====START==="
		#注册 peer0.$org.example, peer1.$org.example 身份实体
		fabric-ca-client register -d -u http://admin:adminpw@$URLorg --id.secret peer0.$org.example.compw --id.name peer0.$org.example.com --id.type peer --id.affiliation com.example.$org
		fabric-ca-client register -d -u http://admin:adminpw@$URLorg --id.secret peer1.$org.example.compw --id.name peer1.$org.example.com --id.type peer --id.affiliation com.example.$org
		echo "============peer0,peer1-$org-Register====END==="
		
		echo "==============peer0,peer1-$org-Enroll====START==="
		# 登记  peer0.$org.example, peer1.$org.example 身份实体，生成 msp 证书文件
		fabric-ca-client enroll -d -u http://peer0.$org.example.com:peer0.$org.example.compw@$URLorg --csr.cn peer0.$org.example.com  --csr.hosts peer0.$org.example.com -M $PEER_DIR/$org.example.com/peers/peer0.$org.example.com/msp --id.affiliation com.example.$org
		fabric-ca-client enroll -d -u http://peer1.$org.example.com:peer1.$org.example.compw@$URLorg --csr.cn peer1.$org.example.com  --csr.hosts peer1.$org.example.com -M $PEER_DIR/$org.example.com/peers/peer1.$org.example.com/msp --id.affiliation com.example.$org
		echo "==============peer0,peer1-$org-Enroll====END==="
		
		echo "==============$org-getcacert====START==="
		#获取服务端 CA 证书文件并保存到 msp 目录下的 cacerts(根CA) 和 intermediatecerts(中间CA) 文件中
		fabric-ca-client getcacert -d -u http://$URLorg -M $PEER_DIR/$org.example.com/msp --id.type client --id.affiliation com.example.$org
		echo "==============$org-getcacert====END==="

		echo "==============$org-Register-Admin & User1====START==="
		#注册 $org 管理员 admin 用户身份实体和普通用户 User1 身份实体
		# fabric-ca-client register -d --id.name Admin@$org.example.com --id.secret Admin.$org.example.compw --id.type client --id.attrs '"hf.Registrar.Roles=client,orderer,peer,user","hf.Registrar.DelegateRoles=client,orderer,peer,user",hf.Registrar.Attributes=*,hf.GenCRL=true,hf.Revoker=true,hf.AffiliationMgr=true,hf.IntermediateCA=true,role=admin:ecert' --id.affiliation com.example.$org
		fabric-ca-client register -d -u http://admin:adminpw@$URLorg --id.name Admin@$org.example.com --id.secret Admin.$org.example.compw --id.type client --id.attrs admin=true:ecert --id.affiliation com.example.$org
		fabric-ca-client register -d -u http://admin:adminpw@$URLorg --id.name User1@$org.example.com --id.secret User1.$org.example.compw --id.type client --id.affiliation com.example.$org
		echo "==============$org-Register-Admin & User1====END==="	
		
		echo "==============$org-enroll-Admin====START==="
		#登记管理员用户，生成管理员用户证书	
		export FABRIC_CA_CLIENT_HOME=$PEER_DIR/$org.example.com/users/Admin@$org.example.com
		fabric-ca-client enroll -d -u http://Admin@$org.example.com:Admin.$org.example.compw@$URLorg --csr.cn Admin.$org.example.com  --csr.hosts Admin.$org.example.com --id.affiliation com.example.$org
		rm $PEER_DIR/$org.example.com/users/Admin@$org.example.com/fabric-ca-client-config.yaml
		echo "==============$org-enroll-Admin====END==="	
		
		echo "==============$org-enroll-User1====START==="
		#登记普通用户 User1 ，生成User1证书	
		export FABRIC_CA_CLIENT_HOME=$PEER_DIR/$org.example.com/users/User1@$org.example.com
		fabric-ca-client enroll -d -u http://User1@$org.example.com:User1.$org.example.compw@$URLorg --csr.cn User1.$org.example.com  --csr.hosts User1.$org.example.com --id.affiliation com.example.$org
		rm $PEER_DIR/$org.example.com/users/User1@$org.example.com/fabric-ca-client-config.yaml
		echo "==============$org-enroll-User1====END==="	
		
		# cp $PEER_DIR/$org.example.com/admin/msp/signcerts/* $PEER_DIR/example.com/msp/admincerts/cert.pem
		# 将管理员用户证书拷贝到 本组织 每个实体 msp 目录下的 admincerts 目录中
		echo "==============$org-copy-admincerts====START==="
		# $org  msp 下的 admincerts
		copyAdminCert $PEER_DIR/$org.example.com/users/Admin@$org.example.com/msp $PEER_DIR/$org.example.com/msp Admin@$org.example.com-cert.pem
		# $org/peers/peer0.example.com/msp 下 的 admincerts
		copyAdminCert $PEER_DIR/$org.example.com/users/Admin@$org.example.com/msp $PEER_DIR/$org.example.com/peers/peer0.$org.example.com/msp Admin@$org.example.com-cert.pem
		# $org/peers/peer1.example.com/msp 下 的 admincerts
		copyAdminCert $PEER_DIR/$org.example.com/users/Admin@$org.example.com/msp $PEER_DIR/$org.example.com/peers/peer1.$org.example.com/msp Admin@$org.example.com-cert.pem	
		# $org/users/Admin@$org.example.com/msp 的 admincerts
		copyAdminCert $PEER_DIR/$org.example.com/users/Admin@$org.example.com/msp $PEER_DIR/$org.example.com/users/Admin@$org.example.com/msp Admin@$org.example.com-cert.pem
		# $org/users/User1@$org.example.com/msp 的 admincerts
		copyAdminCert $PEER_DIR/$org.example.com/users/User1@$org.example.com/msp $PEER_DIR/$org.example.com/users/User1@$org.example.com/msp Admin@$org.example.com-cert.pem
		echo "==============$org-copy-admincerts====END==="

		echo "==============orderer-rm-msp-unimportant-file====START==="
		rmMSP $PEER_DIR/$org.example.com/msp 1

		rmMSP $PEER_DIR/$org.example.com/peers/peer0.$org.example.com/msp 2
		rmMSP $PEER_DIR/$org.example.com/peers/peer1.$org.example.com/msp 2

		rmMSP $PEER_DIR/$org.example.com/users/Admin@$org.example.com/msp 2
		rmMSP $PEER_DIR/$org.example.com/users/User1@$org.example.com/msp 2
		echo "==============orderer-rm-msp-unimportant-file====END==="

		echo "==============orderer-rename-msp-some-file====START==="
		mv $PEER_DIR/$org.example.com/msp/cacerts/*  $PEER_DIR/$org.example.com/msp/cacerts/ca.$org.example.com-cert.pem 	
		
		mv $PEER_DIR/$org.example.com/peers/peer0.$org.example.com/msp/cacerts/* $PEER_DIR/$org.example.com/peers/peer0.$org.example.com/msp/cacerts/ca.$org.example.com-cert.pem 
		mv $PEER_DIR/$org.example.com/peers/peer0.$org.example.com/msp/signcerts/* $PEER_DIR/$org.example.com/peers/peer0.$org.example.com/msp/signcerts/peer0.$org.example.com-cert.pem
		
		mv $PEER_DIR/$org.example.com/peers/peer1.$org.example.com/msp/cacerts/* $PEER_DIR/$org.example.com/peers/peer1.$org.example.com/msp/cacerts/ca.$org.example.com-cert.pem 
		mv $PEER_DIR/$org.example.com/peers/peer1.$org.example.com/msp/signcerts/* $PEER_DIR/$org.example.com/peers/peer1.$org.example.com/msp/signcerts/peer1.$org.example.com-cert.pem
		
		mv $PEER_DIR/$org.example.com/users/Admin@$org.example.com/msp/cacerts/* $PEER_DIR/$org.example.com/users/Admin@$org.example.com/msp/cacerts/ca.$org.example.com-cert.pem
		mv $PEER_DIR/$org.example.com/users/Admin@$org.example.com/msp/signcerts/* $PEER_DIR/$org.example.com/users/Admin@$org.example.com/msp/signcerts/Admin@$org.example.com-cert.pem
		
		mv $PEER_DIR/$org.example.com/users/User1@$org.example.com/msp/cacerts/* $PEER_DIR/$org.example.com/users/User1@$org.example.com/msp/cacerts/ca.$org.example.com-cert.pem
		mv $PEER_DIR/$org.example.com/users/User1@$org.example.com/msp/signcerts/* $PEER_DIR/$org.example.com/users/User1@$org.example.com/msp/signcerts/User1@$org.example.com-cert.pem
		echo "==============orderer-rm-msp-unimportant-file====END==="

	done
		
}

# 生成 $org 下 peer0,peer1 和 Admin,User1 中的 tls 证书 [tlsca.org1.example.com 7058],[tlsca.org2.example.com 7059]
function generateOrgTLS() {
	
	for ((i = 1; i <= 2; i++)) do
		org=org$i
		eval URLtlsorg="$"URLtls$org

		echo "==============init-tls$orgCA-Admin====START==="
		# 登记 tlsCA 管理员身份
		export FABRIC_CA_CLIENT_HOME=$CA_DIR/tls${org}caAdmin
		fabric-ca-client enroll -d -u http://admin:adminpw@$URLtlsorg --csr.cn Admin@tlsca.$org.example.com  --csr.hosts Admin@tlsca.$org.example.com
		echo "==============init-tls$orgCA-Admin====END==="
		
		addOrg # 创建联盟

		echo "==============$org-tls-Register====START==="
		# 在 tlsca 上注册  peer0,peer1 和 Admin,User1 身份实体
		fabric-ca-client register -d -u http://admin:adminpw@$URLtlsorg --id.secret peer0.$org.example.compw --id.name peer0.$org.example.com --id.affiliation com.example.$org
		fabric-ca-client register -d -u http://admin:adminpw@$URLtlsorg --id.secret peer1.$org.example.compw --id.name peer1.$org.example.com --id.affiliation com.example.$org
		
		fabric-ca-client register -d -u http://admin:adminpw@$URLtlsorg --id.secret Admin@$org.example.compw --id.name Admin@$org.example.com --id.affiliation com.example.$org
		fabric-ca-client register -d -u http://admin:adminpw@$URLtlsorg --id.secret User1@$org.example.compw --id.name User1@$org.example.com --id.affiliation com.example.$org
		echo "==============$org-tls-Register====END==="	
		
		echo "==============$org-tls-enroll====START==="
		# 在 tlsca 上登记 orderer.example.com 和 Admin@example.com  身份实体，生成 tls 证书文件
		fabric-ca-client enroll -d --enrollment.profile tls -u http://peer0.$org.example.com:peer0.$org.example.compw@$URLtlsorg -M $PEER_DIR/$org.example.com/peers/peer0.$org.example.com/tls --csr.cn=peer0.$org.example.com --csr.hosts=peer0.$org.example.com --csr.hosts=peer0 --id.affiliation com.example.$org
		fabric-ca-client enroll -d --enrollment.profile tls -u http://peer1.$org.example.com:peer1.$org.example.compw@$URLtlsorg -M $PEER_DIR/$org.example.com/peers/peer1.$org.example.com/tls --csr.cn=peer1.$org.example.com --csr.hosts=peer1.$org.example.com --csr.hosts=peer1 --id.affiliation com.example.$org

		fabric-ca-client enroll -d --enrollment.profile tls -u http://Admin@$org.example.com:Admin@$org.example.compw@$URLtlsorg -M $PEER_DIR/$org.example.com/users/Admin@$org.example.com/tls --id.affiliation com.example.$org
		fabric-ca-client enroll -d --enrollment.profile tls -u http://User1@$org.example.com:User1@$org.example.compw@$URLtlsorg -M $PEER_DIR/$org.example.com/users/User1@$org.example.com/tls --id.affiliation com.example.$org
		echo "==============$org-tls-enroll====END==="

		echo "==============$org-copy-tlscacerts====START==="
		# $org.example.com/msp/tlscacerts
		copytlsCaCerts $PEER_DIR/$org.example.com/users/Admin@$org.example.com/tls $PEER_DIR/$org.example.com/msp tlsca.$org.example.com-cert.pem
		# $org.example.com/peers/peer0,peer1.example.com/msp/tlscacerts
		copytlsCaCerts $PEER_DIR/$org.example.com/users/Admin@$org.example.com/tls $PEER_DIR/$org.example.com/peers/peer0.$org.example.com/msp tlsca.$org.example.com-cert.pem
		copytlsCaCerts $PEER_DIR/$org.example.com/users/Admin@$org.example.com/tls $PEER_DIR/$org.example.com/peers/peer1.$org.example.com/msp tlsca.$org.example.com-cert.pem
		# $org.example.com/users/Admin,User1@example.com/msp/tlscacerts
		copytlsCaCerts $PEER_DIR/$org.example.com/users/Admin@$org.example.com/tls $PEER_DIR/$org.example.com/users/Admin@$org.example.com/msp tlsca.$org.example.com-cert.pem
		copytlsCaCerts $PEER_DIR/$org.example.com/users/Admin@$org.example.com/tls $PEER_DIR/$org.example.com/users/User1@$org.example.com/msp tlsca.$org.example.com-cert.pem
		echo "==============$org-copy-tlscacerts====END==="

		# cp $PEER_DIR/example.com/orderer/tls/keystore/* $PEER_DIR/example.com/orderer/tls/server.key
		# cp $PEER_DIR/example.com/orderer/tls/signcerts/* $PEER_DIR/example.com/orderer/tls/server.crt
		# cp $PEER_DIR/example.com/orderer/tls/tlscacerts/* $PEER_DIR/example.com/orderer/tls/ca.crt
		copyServerTls $PEER_DIR/$org.example.com/peers/peer0.$org.example.com/tls
		copyServerTls $PEER_DIR/$org.example.com/peers/peer1.$org.example.com/tls
		
		copyClientTls $PEER_DIR/$org.example.com/users/Admin@$org.example.com/tls
		copyClientTls $PEER_DIR/$org.example.com/users/User1@$org.example.com/tls

		echo "==============org-rm-tls-unimportant-file====START==="
		rmTLS $PEER_DIR/$org.example.com/peers/peer0.$org.example.com/tls
		rmTLS $PEER_DIR/$org.example.com/peers/peer1.$org.example.com/tls

		rmTLS $PEER_DIR/$org.example.com/users/Admin@$org.example.com/tls
		rmTLS $PEER_DIR/$org.example.com/users/User1@$org.example.com/tls
		echo "==============org-rm-tls-unimportant-file====END==="

	done
}

# Ask user for confirmation to proceed
function askProceed() {
	read -p "Continue? [Y/n] " ans
	case "$ans" in
	y | Y | "")
		echo "proceeding ..."
		;;
	n | N)
		echo "exiting..."
		exit 1
		;;
	*)
		echo "invalid response"
		askProceed
		;;
	esac
}

# 生成ca的流程
function makeCAControl() {
	echo "######################################################################"
	echo "#---------------------get CA with CA Servet start--------------------#"
	echo "######################################################################"
	#clearPath
	generateOrdererMSP
	generateOrdererTLS
	
	generateOrgMSP 
	generateOrgTLS

	touchConfig

	echo "######################################################################"
	echo "#---------------------get CA with CA Server END----------------------#"
	echo "######################################################################"
}

sleep 1

makeCAControl

exit 0

# id:
	#   name: Admin@example.com
	#   type: client
	#   affiliation: com.example
	#   maxenrollments: 0
	#   attributes:
	#     - name: hf.Registrar.Roles
	#       value: client,orderer,peer,user
	#     - name: hf.Registrar.DelegateRoles
	#       value: client,orderer,peer,user
	#     - name: hf.Registrar.Attributes
	#       value: "*"
	#     - name: hf.GenCRL
	#       value: true
	#     - name: hf.Revoker
	#       value: true
	#     - name: hf.AffiliationMgr
	#       value: true
	#     - name: hf.IntermediateCA
	#       value: true
	#     - name: role
	#       value: admin
	#       ecert: true