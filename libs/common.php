<?php
error_reporting(E_ALL);
ini_set('display_errors', 1);
include_once 'constants.php';
include_once 'Security.php';

class common {

    /**
     * getRandomCode Method
     * 
     * @param $length
     * @param $type
     * @return string
     */
    public function getRandomCode($length, $type = null) {
        // Random characters
        if ($type == 'alphabetic') {
            $keys = array_merge(range('a', 'z'), range('A', 'Z'));
        } elseif ($type == 'numeric') {
            $characters = array("0", "1", "2", "3", "4", "5", "6", "7", "8", "9");
            $keys = array_merge(range(0, 9));
        } else {
            $keys = array_merge(range(0, 9), range('a', 'z'), range('A', 'Z'));
        }
        // set the array
        $key = '';
        for ($i = 0; $i < $length; $i++) {
            $key .= $keys[array_rand($keys)];
        }
        // display random key
        return $key;
    }

    /**
     * Function used to encrypt data with GSP app-key
     * @param string $data
     * @param type $appKey
     * @return string
     */
    public function EncryptWithAppKey($data, $appKey) {
        $iv = $appKey; // pass app-key as $iv
        $blocksize = 16;
        $pad = $blocksize - (strlen($data) % $blocksize);
        $data = $data . str_repeat(chr($pad), $pad);
        return bin2hex(mcrypt_encrypt(MCRYPT_RIJNDAEL_128, $appKey, $data, MCRYPT_MODE_CBC, $iv));
    }

    /**
     * Encrypt App-key with GSP public key
     */
    public function encryptAspPubliKey($data) {
        $fp = fopen(__dir__ . "/files/server.crt", "r");
        $public = fread($fp, 8192);
        fclose($fp);
        openssl_public_encrypt($data, $encryptedData, $public, OPENSSL_PKCS1_PADDING);
        // Return encrypted app-key
        return base64_encode($encryptedData);
    }
    
    /**
     * This method used to encrypt data with EK
     *
     */
    public function encryptData($value, $ek) {
        $key = base64_decode($ek);
        $response['error'] = false;
        $response['data'] = Security::encrypt($value, $key);

        return $response;
    }
    
    /**
     * decryptData Method
     * @param string $data
     * @param string $appkey
     * @return string
     */
    public function decryptData($data, $appkey) {
        $value = $data;
        $key = base64_decode($appkey); //16 Character Key
        return Security::decrypt($value, $key);
    }

    /**
     * getAccessToken method
     * 
     * Method used to get access-token from GSP(Masters India)
     * @param type $JsonAspUser
     * @param type $appKey
     * @return string
     */
    public function getAccessToken() {
       
        //fetch GSP user data
        $aspUserInfo = unserialize(accessTokenInfo);
        $aspUserData['username'] = $aspUserInfo['username'];
        $aspUserData['password'] = $aspUserInfo['password'];
        $aspUserData['client_id'] = $aspUserInfo['client_id'];
        $aspUserData['client_secret'] = $aspUserInfo['client_secret'];
        $aspUserData['grant_type'] = $aspUserInfo['grant_type'];
        $JsonAspUser = json_encode($aspUserData);
        //generate app-key of 16 character length
        $appKey = $this->getRandomCode(16);
        //encrypt data with app-key
        $encryptedWithAppKey = $this->EncryptWithAppKey($JsonAspUser, $appKey);
        //encrypt app-key with Public key
        $encryptedWithPub = $this->encryptAspPubliKey($appKey);
        if ($encryptedWithPub) {
            //prepare data for access token
            $EncryptedData['credentials_data'] = $encryptedWithAppKey;
            $EncryptedData['app_key'] = $encryptedWithPub;
            $HeaderOption = array('Content-Type: application/json');
            $json_encode_data = json_encode($EncryptedData);
            //send request to get access token
            $GSPApiUrl = unserialize(requestUrl);
            $url = $GSPApiUrl['access_token'];
            $result = $this->sendGSPRequest($url, $json_encode_data, 'POST');
            if (isset($result) && isset($result->accessToken)) {
                $response['error'] = false;
                $response['access_token'] = $result->accessToken;
                $response['expire'] = $result->expires_in;
                $response['app_key'] = $appKey;
            } else{
                if (isset($result->error->error_cd)) {
                    if (isset($result->error->error_description->error)) {
                        $msg = $result->error->error_description->error_description;
                    }elseif(isset($result->error->error_description)) {
                        $msg = $result->error->error_description;
                    } else {
                        $msg = $result->error_description;
                    }
                }else{
                    $msg = "Service not available. Please, try after sometime";
                }
                $response['error'] = true;
                $response['message'] = $msg;
            }
        } else {
            $response['error'] = true;
            $response['message'] = 'Error in encrypting with public key';
        }

        return $response;
    }
    




     /**
     * ewayEncryption method
     * Method used to encrypt app key for E-Inv API
     * @param string $pass
     * @access public
     * @return string
     */
     public function eWayEncryption($pass = null) {


        if ($pass != null || $pass != '') {
            $appKey = base64_encode($pass);
            
        } else {
            $appKey = base64_encode($this->getRandomCode(32));
        }
        
        //read eWay pem file        
        $fp = fopen(__dir__."/PublicKey/Eway_publickey.pem", "r");
        
        $pub_key = fread($fp, 8192);
        
        fclose($fp);
        
        openssl_public_encrypt(base64_decode($appKey), $crypttext, $pub_key);
        
        $res = base64_encode($crypttext);
        
        $response['flat_app_key'] = $appKey;
        $response['encrypt_app_key'] = $res;
        //print_r($response);
        return $response;
    }
    
    /**
     * eWayApiAuthenticate method
     * method used to authenticate TP from E-Inv system
     * @return array
     */
    public function EwayApiAuthenticate($EwayUsername,$EwayPassword,$gstin,$access_token,$ASP_client_id,$ASP_app_key,$gstin) { 

     $other_param_data['access_token'] = $access_token;
     $other_param_json = json_encode($other_param_data);
        //encrypt data with app-key
     $encryptedWithAppKey = $this->EncryptWithAppKey($other_param_json, $ASP_app_key);

        //$GspInfo = unserialize(GspInfo);

     $app_key_data = $this->eWayEncryption();
        
     $reqData['action'] = "ACCESSTOKEN";      
     $reqData['username'] = $EwayUsername;
     $reqData['password'] = $EwayPassword;
     $reqData['app_key'] = $app_key_data['flat_app_key'];
     
    
     $encryptReqData=$this->eWayEncryption(base64_encode(json_encode($reqData)));
    

     $fields['Data']= $encryptReqData['encrypt_app_key'];
     $fields['other_parameters'] = $encryptedWithAppKey;
     //echo "<strong>Request JSON Payload</strong><br><br>";
      $data = json_encode($fields);
     $GstrApiUrl = unserialize(requestUrl);
     $url = $GstrApiUrl['host'].'/ewaybillapi/v1.03/authenticate';
        //send user's header
     $otherDetail['client-id'] = $ASP_client_id;
     $otherDetail['Gstin'] = $gstin;
     $encodedOtherDetails = json_encode($otherDetail);     
     $result = $this->sendGSPRequest($url, $data, 'POST', $encodedOtherDetails);
         
     if ($result) {
        if (isset($result->status) && $result->status == 1) {
                //decrypt sek with app key
                $sek = $result->sek; //temp
                $ek = $this->decryptData($sek, $app_key_data['flat_app_key']);
                if ($ek) {
                    $response['error'] = false;
                    $response['sek'] = $result->sek;
                    $response['authtoken'] = $result->authtoken;
                    $response['eway_expiry'] = isset($result->expiry) ? $result->expiry : 360;
                    $response['flat_app_key'] = $app_key_data['flat_app_key'];
                    //$response['eway_ek'] = $ek;
                    //$response['eway_app_key'] = $app_key_data['flat_app_key'];
                    
                } else {
                    $response['error'] = true;
                    $response['message'] = 'Error in decrypting sek in E-way'; //temp
                }
            } else {
                $eway_error_codes = unserialize(eway_error_codes);
                if (isset($result->status) && $result->status == 0) {
                    $error_code=json_decode(base64_decode($result->error));
                    if(isset($eway_error_codes[$error_code->errorCodes])){
                        $msg = $eway_error_codes[$error_code->errorCodes];
                    }else{
                        $msg = base64_decode($result->error);
                    }
                }else if (isset($result->error->message)) {
                    $msg = $result->error->message;
                } elseif (isset($result->error->desc)) {
                    $msg = $result->error->desc;
                } elseif (isset($result->message)) {
                    $msg = $result->message;
                } elseif (isset($result->error_msg)) {
                    $msg = $result->error_msg;
                } elseif (isset($result->error->error_cd)) {
                    if (isset($result->error->error_description->error_description)) {
                        $msg = $result->error->error_description->error_description;
                    } elseif (isset($result->error->error_description)) {
                        $msg = $result->error->error_description;
                    }
                }elseif (isset($result->Message)) {
                    $msg = $result->Message;
                } else {
                    $msg = 'There seems to be too much load on NIC server, please try after sometime';
                }
                $response['error'] = true;
                $response['message'] = $msg;
            }
        } else {
            $response['error'] = true;
            $response['message'] = 'There seems to be too much load on NIC server, please try after sometime';
        }
        //print_r($response);die;
        return $response;
    }
    

    /**
     * saveEwayData method
     * Method used to save data to the E-Way system
     * 
     * @param string $data_json (Request JSON Payload)
     * @param string $action
     * @param string $gstin
     * @param string $eway_auth_token
     * @param string $eway_app_key
     * @param string $eway_sek
     * @param string $access_token
     * @param string $ASP_client_id
     * @param string $ASP_app_key
     * @return array
     */
    public function saveEwayData($data_json, $action,$gstin,$eway_auth_token,$eway_app_key,$eway_sek,$access_token,$ASP_client_id,$ASP_app_key) {
       

    $auth_token=$eway_auth_token;
    $flat_app_key=$eway_app_key;
    $sek=$eway_sek;

    $other_param_data['access_token'] = $access_token;       
    $other_param_json = json_encode($other_param_data);

        //encrypt data with app-key
    $encryptedWithAppKey = $this->EncryptWithAppKey($other_param_json, $ASP_app_key);
        //prepare user's field data    
        //get $ek
    $ek = $this->decryptData($sek, $flat_app_key);

        //encrypt data with EK
    $enc = $this->encryptData($data_json, base64_encode($ek));

    if (!isset($enc['data'])) {
        $response['error'] = true;
        $response['message'] = "Invalid ek";
        return $response;
    }

    $fields['action'] = $action;
        $fields['data'] = $enc['data']; //base64 encoded data
        $fields['other_parameters'] = $encryptedWithAppKey;
        $data = json_encode($fields);
        $GstrApiUrl = unserialize(requestUrl);
        $url = $GstrApiUrl['host'].'/ewaybillapi/v1.03/ewayapi';
      
        $method = 'POST';
        //send user's header
        $otherDetail['authtoken'] = $auth_token;
        $otherDetail['gstin'] = $gstin;
        $otherDetail['client-id'] = $ASP_client_id;        
        $encodedOtherDetails = json_encode($otherDetail);
        
        //send data to GST System
        $result = $this->sendGSPRequest($url, $data, $method, $encodedOtherDetails);
        //print_r($result);die;
        if (isset($result->status) && $result->status == 1) {
            $encodedData = $this->decryptData($result->data, base64_encode($ek));
            $response['error'] = false;
            $response['data'] = $encodedData;
            //$response['reqData'] = base64_encode($data_json);
        }  else {

            $eway_error_codes = unserialize(eway_error_codes);
            if (isset($result->status) && $result->status == 0) {
                $error_code=json_decode(base64_decode($result->error));

                //check auth token get expired or invalid(238, 105, 106). if so, regenerate authtoken and then generate Eway bill
                if($error_code->errorCodes=='238' || $error_code->errorCodes==238 || $error_code->errorCodes=='105' || $error_code->errorCodes==105 || $error_code->errorCodes=='106' || $error_code->errorCodes==106){
                   $getEwayAccessToken=$this->getEwayAccessToken($gstin,true);
                   if($getEwayAccessToken['error']!=true){
                       return $this->saveEwayData($data_json,$action,$gstin,$redirect_url = null);
                   }else{
                       $response['error'] = true;
                       $response['message'] = $getEwayAccessToken['message'];
                       return $response;
                   }
               }
            if(isset($eway_error_codes[$error_code->errorCodes])){
                $msg = $eway_error_codes[$error_code->errorCodes];
            }else{
                $msg = base64_decode($result->error);
            }

        }elseif (isset($result->error->message)) {
            $msg = $result->error->message;
        } elseif (isset($result->error->desc)) {
            $msg = $result->error->desc;
        } elseif (isset($result->message)) {
            $msg = $result->message;
        } elseif (isset($result->error_msg)) {
            $msg = $result->error_msg;
        } elseif (isset($result->error->error_cd)) {
            if (isset($result->error->error_description->error_description)) {
                $msg = $result->error->error_description->error_description;
            } elseif (isset($result->error->error_description)) {
                $msg = $result->error->error_description;
            }
        }elseif (isset($result->Message)) {
            $msg = $result->Message;
        } else {
            $msg = 'There seems to be too much load on NIC server, please try after sometime';
        }
        $response['error'] = true;
        $response['message'] = $msg;
    }
    return $response;
}
    /**
     * getEwayData method
     * Method used to get data from E-Way system
     *
     */
    public function getEwayData($eway_No,$action,$gstin,$eway_auth_token,$eway_app_key,$eway_sek,$access_token,$ASP_client_id,$ASP_app_key) {
        $auth_token=$eway_auth_token;
        $flat_app_key=$eway_app_key;
        $sek=$eway_sek;        
        $other_param_data['access_token'] = $access_token;

        $other_param_json = json_encode($other_param_data);

        //encrypt data with app-key
        $encryptedWithAppKey = $this->EncryptWithAppKey($other_param_json, $ASP_app_key);

        //get $ek
        $ek = $this->decryptData($sek, $flat_app_key);
        
        $response['error']=false;
        $GstrApiUrl = unserialize(requestUrl);
        $url = $GstrApiUrl['host'];
        if($action=='GetEwayBill'){
           if(isset($eway_No) && $eway_No!=''){
            $url .= '/ewaybillapi/v1.03/ewayapi/GetEwayBill?ewbNo='.$eway_No;
        }else{
            $response['error']=true;
            $response['message']='irn_no is missing in request';
        }
    }else{
        $response['error']=true;
        $response['message']='Wrong action in request';
    }
        //send user's header
    $otherDetail['authtoken'] = $auth_token;
    $otherDetail['gstin'] = $gstin;
    $otherDetail['client-id'] = $ASP_client_id;
    $encodedOtherDetails = json_encode($otherDetail);
    
     $url .= '&other_parameters=' . $encryptedWithAppKey;

    
    if($response['error']==false){
        $result = $this->sendGSPRequest($url, $data=null, $method=null, $encodedOtherDetails);
        if (isset($result->status) && $result->status == 1) {
           $rek = $result->rek; //temp
            //get key from rek to encrypt data in response from Eway system
            $key = $this->decryptData($rek, base64_encode($ek)); //temp
            //decrypt Data from key
            $encodedData = $this->decryptData($result->data, base64_encode($key));
            $response['error'] = false;
            $response['data'] = $encodedData;

        } else {
             $eway_error_codes = unserialize(eway_error_codes);
            if (isset($result->status) && $result->status == 0) {
                $error_code=json_decode(base64_decode($result->error));
                //check auth token get expired or invalid(238, 105, 106). if so, regenerate authtoken and then call again resuested API
            
             if(isset($eway_error_codes[$error_code->errorCodes])){
                $msg = $eway_error_codes[$error_code->errorCodes];
            }else{
                $msg = base64_decode($result->error);
            }

        }elseif (isset($result->error->message)) {
                $msg = $result->error->message;
            } elseif (isset($result->error->desc)) {
                $msg = $result->error->desc;
            } elseif (isset($result->message)) {
                $msg = $result->message;
            } elseif (isset($result->error_msg)) {
                $msg = $result->error_msg;
            } elseif (isset($result->error->error_cd)) {
                if (isset($result->error->error_description->error_description)) {
                    $msg = $result->error->error_description->error_description;
                } elseif (isset($result->error->error_description)) {
                    $msg = $result->error->error_description;
                }
            }elseif (isset($result->Message)) {
                $msg = $result->Message;
            }elseif (isset($result->error)) {
                $msg = $result->error;
            } else {
                $msg = 'There seems to be too much load on NIC server, please try after sometime';
            }
            $response['error'] = true;
            $response['message'] = $msg;
        }
        return $response;
    }
}

    /**
     * send request
     */
    function sendGSPRequest($url, $data = null, $method = null, $other_detail_json = null) {
        $HeaderOption = array('Content-Type: application/json');
        if ($other_detail_json != null) {
            $other_detail = json_decode($other_detail_json, true);
            foreach ($other_detail as $key => $value) {
                array_push($HeaderOption, $key . ':' . $value);
            }
        }
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        
        curl_setopt($ch, CURLOPT_HTTPHEADER, $HeaderOption);
        if ($method == 'POST' || $method == 'PUT') {
            if ($method == 'PUT') {
                curl_setopt($ch, CURLOPT_CUSTOMREQUEST, "PUT");
            } else {
                curl_setopt($ch, CURLOPT_POST, 1);
            }
            curl_setopt($ch, CURLOPT_POSTFIELDS, $data);
        }
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_VERBOSE, true);
        curl_setopt($ch, CURLOPT_STDERR, fopen('php://stderr', 'w'));
        // Execute post
        $result = curl_exec($ch);
        $status_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $curl_err = curl_error($ch);
        curl_close($ch);
        $result2 = json_decode($result);


      return $result2;
  }

}
