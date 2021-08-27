<?php

include_once './libs/common.php';

//accessToken();
//ewayAuthToken();
//generateEwayBill();
//getEwayBill();
//cancelEwayBill();

function accessToken(){
	$common = new common();
	$resp = $common->getAccessToken();

	echo "<br><br><strong>Response</strong><br><br>";
	echo '<pre>';
	print_r($resp);
}


function ewayAuthToken(){
	$aspUserInfo = unserialize(accessTokenInfo);
	$ewayGstinInfo = unserialize(ewayGstinInfo);
	$common = new common();
	//get Authentication from Masters India
	$respponseAccessToken = $common->getAccessToken();
	echo "<br><br><strong>Access Token Response From Masters India</strong><br><br>";
	echo '<pre>';
	print_r($respponseAccessToken);

	$gstin=$ewayGstinInfo['gstin'];//Eway GSTIN
	$EwayUsername=$ewayGstinInfo['EwayUsername'];
	$EwayPassword=$ewayGstinInfo['EwayPassword'];
	$access_token=$respponseAccessToken['access_token'];//Access_token from Masters India
	$ASP_app_key=$respponseAccessToken['app_key'];//App key from Masters India
	$ASP_client_id=$aspUserInfo['client_id'];//Shared Client Id 

	//Get Authtoken from Eway System
	$responseAuthToken = $common->EwayApiAuthenticate($EwayUsername,$EwayPassword,$gstin,$access_token,$ASP_client_id,$ASP_app_key,$gstin);
	echo "<br><br><strong>AuthToken Response</strong><br><br>";
	print_r($responseAuthToken);die;

}

function generateEwayBill() {


	$aspUserInfo = unserialize(accessTokenInfo);
	$ewayGstinInfo = unserialize(ewayGstinInfo);
	$common = new common();

	$respponseAccessToken = $common->getAccessToken();

	$gstin=$ewayGstinInfo['gstin'];//Eway GSTIN
	$EwayUsername=$ewayGstinInfo['EwayUsername'];
	$EwayPassword=$ewayGstinInfo['EwayPassword'];
	$access_token=$respponseAccessToken['access_token'];//Access_token from Masters India
	$ASP_app_key=$respponseAccessToken['app_key'];//App key from Masters India
	$ASP_client_id=$aspUserInfo['client_id'];//Shared Client Id 

	//Get Authtoken from Eway System
	$responseAuthToken = $common->EwayApiAuthenticate($EwayUsername,$EwayPassword,$gstin,$access_token,$ASP_client_id,$ASP_app_key,$gstin);
	//print_r($responseAuthToken);die;
	$eway_auth_token=$responseAuthToken['authtoken'];
	$eway_app_key=$responseAuthToken['flat_app_key'];
	$eway_sek=$responseAuthToken['sek'];
	$no = $common->getRandomCode(5);
	$docNo = 'Test/'.$no;

	$json_data = '{"supplyType":"I","subSupplyType":"2","docType":"BOE","docNo":"'.$docNo.'","docDate":"12\/03\/2021","fromGstin":"URP","fromTrdName":"CS02 CLASSIC STRIPES PVT. LTD.","fromAddr1":"CSPL PELHAR UNIT","fromAddr2":"Survey No.188,192-194,210-213","fromPlace":"Taluka-Vasai, Palghar","fromPincode":400099,"fromStateCode":99,"toGstin":"05AAAAU6537D1ZO","toTrdName":"M.P TRADERS","toAddr1":"RAIPUR","toAddr2":"SHREENATH MARKETING","toPlace":"RAIPUR","toPincode":263001,"toStateCode":5,"transporterId":"05AAABB0639G1Z8","transporterName":"PRAKASH TRANSPORT SERVICE","transDocNo":"ABCD1234","transDocDate":"13\/03\/2021","transMode":"1","transDistance":1785,"vehicleNo":"MH04GM4890","vehicleType":"R","itemList":[{"productName":"SCREEN PRINTED SELF ADHESIVE PVC STICKERS","productDesc":"0281.006.240-25L PHASE SENSOR (028100624025L) (HOT FILM AIRMASS METER)","hsnCode":"90268090","quantity":9360,"qtyUnit":"NOS","taxableAmount":3434198.91,"igstRate":18,"cessRate":0,"cgstRate":0,"sgstRate":0,"cessNonAdvol":0}],"totalValue":3434198.91,"cgstValue":0,"sgstValue":0,"igstValue":618155.8,"cessValue":0,"cessNonAdvolValue":0,"otherValue":9.64,"totInvValue":4052364.71,"subSupplyDesc":"","actFromStateCode":27,"actToStateCode":5,"transactionType":3}';
	$action='GENEWAYBILL';
	//print_r($json_data);die;
	$responseAuthToken = $common->saveEwayData($json_data, $action,$gstin,$eway_auth_token,$eway_app_key,$eway_sek,$access_token,$ASP_client_id,$ASP_app_key);
	echo "<br><br><strong>Response</strong><br><br>";
	print_r($responseAuthToken);die;

}

function getEwayBill(){
	$aspUserInfo = unserialize(accessTokenInfo);
	$ewayGstinInfo = unserialize(ewayGstinInfo);
	$common = new common();

	$respponseAccessToken = $common->getAccessToken();

	$gstin=$ewayGstinInfo['gstin'];//Eway GSTIN
	$EwayUsername=$ewayGstinInfo['EwayUsername'];
	$EwayPassword=$ewayGstinInfo['EwayPassword'];
	$access_token=$respponseAccessToken['access_token'];//Access_token from Masters India
	$ASP_app_key=$respponseAccessToken['app_key'];//App key from Masters India
	$ASP_client_id=$aspUserInfo['client_id'];//Shared Client Id 

	//Get Authtoken from Eway System
	$responseAuthToken = $common->EwayApiAuthenticate($EwayUsername,$EwayPassword,$gstin,$access_token,$ASP_client_id,$ASP_app_key,$gstin);

	$eway_auth_token=$responseAuthToken['authtoken'];
	$eway_app_key=$responseAuthToken['flat_app_key'];
	$eway_sek=$responseAuthToken['sek'];

	$eway_No='361002704645';
	$action='GetEwayBill';
	$responseAuthToken = $common->getEwayData($eway_No,$action,$gstin,$eway_auth_token,$eway_app_key,$eway_sek,$access_token,$ASP_client_id,$ASP_app_key);
	echo "<br><br><strong>Response</strong><br><br>";
	echo "<pre>";
	print_r($responseAuthToken);

}

function cancelEwayBill()
{
	$aspUserInfo = unserialize(accessTokenInfo);
	$ewayGstinInfo = unserialize(ewayGstinInfo);
	$common = new common();

	$respponseAccessToken = $common->getAccessToken();

$gstin=$ewayGstinInfo['gstin'];//Eway GSTIN
$EwayUsername=$ewayGstinInfo['EwayUsername'];
$EwayPassword=$ewayGstinInfo['EwayPassword'];
$access_token=$respponseAccessToken['access_token'];//Access_token from Masters India
$ASP_app_key=$respponseAccessToken['app_key'];//App key from Masters India
$ASP_client_id=$aspUserInfo['client_id'];//Shared Client Id 

//Get Authtoken from Eway System
$responseAuthToken = $common->EwayApiAuthenticate($EwayUsername,$EwayPassword,$gstin,$access_token,$ASP_client_id,$ASP_app_key,$gstin);

$eway_auth_token=$responseAuthToken['authtoken'];
$eway_app_key=$responseAuthToken['flat_app_key'];
$eway_sek=$responseAuthToken['sek'];

$eway_No = '361002704645';
$json_data = '{"ewbNo":"'.$eway_No.'","cancelRsnCode":4,"cancelRmrk":"Cancelled the order"}';
$action='CANEWB';
$responseAuthToken = $common->saveEwayData($json_data, $action,$gstin,$eway_auth_token,$eway_app_key,$eway_sek,$access_token,$ASP_client_id,$ASP_app_key);
echo "<br><br><strong>Response</strong><br><br>";
print_r($responseAuthToken);

}

?>