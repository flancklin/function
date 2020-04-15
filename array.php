<?php


/**
 * 把一个数组输出到界面。在界面上直接复制粘贴，粘贴后是可用的代码。
 * 不支持数组元素是对象的情况
 * @param $array
 * @return string
 */
function printArrayToCode(array $array)
{
    $str = "[";
    foreach ($array as $key => $value) {
        if(is_integer($key)){
            if(is_array($value)){
                $str .= printArrayToCode($value);
            }else{
                if ($value === true) {
                    $str .= "true";
                } elseif ($value === false) {
                    $str .= "false";
                } elseif ($value === 'true') {
                    $str .= "'true'";
                } elseif ($value === 'false') {
                    $str .= "'false'";
                } elseif ($value === NULL) {
                    $str .= "NULL";
                } elseif (is_string($value)) {
                    $str .= "'{$value}'";
                } else {
                    $str .= $value;
                }
            }
        }else{
            if(is_array($value)){
                $str .= "'{$key}'=>".printArrayToCode($value);
            }else{
                $str .= "'{$key}'=>";
                if ($value === true) {
                    $str .= "true";
                } elseif ($value === false) {
                    $str .= "false";
                } elseif ($value === 'true') {
                    $str .= "'true'";
                } elseif ($value === 'false') {
                    $str .= "'false'";
                } elseif ($value === NULL) {
                    $str .= "NULL";
                } elseif (is_string($value)) {
                    $str .= "'{$value}'";
                } else {
                    $str .= $value;
                }
            }
        }
        $str .= ',';
    }
    $str = trim($str, ',');
    $str .= "]";
    return $str;
}