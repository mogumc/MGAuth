<?php
error_reporting(0);//Debug off Switch 1 to On

//  MGAuth Version 1.0
//  Please import base.sql before use
//  Need:
//  PHP Version 7.4+ MySQL Version 4.6+

//Please Fill This Info
$link = "localhost";
$name = "";
$pwd = "";
$dbname = "";
$port = "1443";
//Please Fill This Info

$appid = $_GET['appid'];
$token = $_GET['key'];
$retoken = $_GET['rkey'];

if(!$appid){
    header("Content-Type: text/json;charset=utf-8");
    die(json_encode(array('erron'=>'900','msg'=>'用户未登录'),JSON_UNESCAPED_UNICODE));    
}

$unconn = json_encode(array('erron'=>'9000','msg'=>'用户信息身份认证失败'),JSON_UNESCAPED_UNICODE);
$conn = mysqli_connect($link,$name,$pwd,$dbname,$port) or die($unconn);  
if($appid!='' or $appid!=null or !empty($appid)){
    if(!strstr($_SERVER['REQUEST_URI'],'/appid')){
        $sqly = "select * from appid where appid = ? and token = ?";
        $stmt = $conn->prepare($sqly) or die($unconn);
        $stmt->bind_param('ss',$appid,$token) or die($unconn);
        $stmt->execute() or die($unconn);
        $result = $stmt->get_result();
        if($result->num_rows<1){
            header("Content-Type: text/json;charset=utf-8");
            die($unconn);    
        } else {
            $infos = $result->fetch_assoc();  
            $utime = date('d',time());
            $thetime = $infos['utime'];
            $tot = $infos['tot'];
        if($thetime == $utime){
            $times = $infos['times'];
        } else {
            $times = $tot;
        }
        if((int)$times-1<0){
            header("Content-Type: text/json;charset=utf-8");
            die(json_encode(array('erron'=>'100','msg'=>'配额已用尽，等待次日刷新','times'=>$times,'tot'=>$tot),JSON_UNESCAPED_UNICODE));   
        } else {
            $times = (int)$times-1;
            $times = (string)$times;
            $sqly = "UPDATE appid SET times = ?,utime = ? where appid = ? and token = ?";
            $stmt = $conn->prepare($sqly) or die($unconn);
            $stmt->bind_param('ssss',$times,$utime,$appid,$token) or die($unconn);
            $stmt->execute() or die($unconn);
        }
        }
    } else {
        header("Content-Type: text/json;charset=utf-8");
        $sqly = "select * from appid where appid = ?";
        $stmt = $conn->prepare($sqly) or die($unconn);
        $stmt->bind_param('s',$appid) or die($unconn);
        $stmt->execute() or die($unconn);
        $result = $stmt->get_result();
        if($result->num_rows>=1){
            $infos = $result->fetch_assoc();
            $rtoken = $infos['retoken'];
            $thetime = $infos['utime']; 
            $usetimes = $infos['times'];
            $tot = $infos['tot'];
            $ttken = $infos['token'];
            $utime = date('d',time()); 
            if(!$rtoken){
                $rtoken = 're_'.sha1(md5($appid).md5($utime).sha1('MGAPI').md5('mgapikey'));
                $sqly = "UPDATE appid SET retoken = ? where appid = ?";
                $stmt = $conn->prepare($sqly) or die($unconn);
                $stmt->bind_param('ss',$rtoken,$appid) or die($unconn);
                $stmt->execute() or die($unconn);
                die(json_encode(array('erron'=>'0','msg'=>'ReKey生成成功！ReKey仅可生成一次，用于刷新Key请妥善保管请勿泄露！','rkey'=>$rtoken),JSON_UNESCAPED_UNICODE));
            } elseif($rtoken==$retoken){
                $token = md5($appid.md5(md5($rtoken).md5($appid).md5($rtoken).sha1('MGAuth')).md5($utime).time());
                $sqly = "UPDATE appid SET token = ? where appid = ?";
                $stmt = $conn->prepare($sqly) or die($unconn);
                $stmt->bind_param('ss',$token,$appid) or die($unconn);
                $stmt->execute() or die($unconn);
                die(json_encode(array('erron'=>'0','msg'=>'Token生成成功！刷新后原Token将失效！','token'=>$token),JSON_UNESCAPED_UNICODE));
            } elseif($rtoken!=$retoken){
                die($unconn);
            }
        } else {
            die($unconn);
        }
    }
} else {
    header("Content-Type: text/json;charset=utf-8");
    die(json_encode(array('erron'=>'900','msg'=>'用户未登录'),JSON_UNESCAPED_UNICODE));
}
