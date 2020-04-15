<?php


/**
 * array_merge($param1,$param2,$param3,$param4,$param5)
 * 这个函数可以接受无限个参数。这是底层封装，这是C语言
 * 哪用php能否实现相同的功能呢？
 *
 *func_get_args()   获取全部的参数
 *func_num_args()   判断参数的个数
 * func_get_arg(2)  获取第num个参数的值（0是开始第一个） //本例返回值['c']
 */

function test($p1, $p2)
{
    $args = func_get_args();
    var_dump($p1, $p2); //$p1 = ['a']     $p2 = ['b']
    var_dump($args);
    //[
    //  0 => ['a'],
    //  1 => ['b'],
    //  2 => ['c']
    //  3 => ['d']
    //]
}

function test2($p1,$p2,...$args){
    var_dump($p1, $p2);//$p1 = ['a']     $p2 = ['b']
    var_dump($args);
//    [
//        0 => ['c'],
//        1 => ['d']
//    ]
}

test(['a'], ['b'], ['c'], ['d']);