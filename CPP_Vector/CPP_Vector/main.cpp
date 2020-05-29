//
//  main.cpp
//  CPP_Vector
//
//  Created by Zewen Jin on 2019/9/2.
//  Copyright © 2019 Zewen Jin. All rights reserved.
//

#include <iostream>
#include <vector>
using namespace std;

int main(int argc, const char * argv[]) {
    //第一种：不传参数
    vector<int> vint;
    vector<char> vchar;
    vector<string> vstring;
    //第二种：传一个参数 相当于开辟了一个数组
    vector<int> vint2(5);
    vector<char> vchar2(5);
    vector<string> vstring2(5);
    //第三种：参数一表示vector大小，第二个参数对其进行初始化
    vector<int> vint3(5,0);
    vector<char> vchar3(5,'a');
    vector<string> vstring3(5,"abc");
    //第四种：传一段迭代器区间
    vector<int> vint4(vint3.begin(),vint3.end());
    vector<char> vchar4(vchar3.begin(),vchar3.end());
    vector<string> vstring4(vstring3.begin(),vstring3.end());
    //第五种：利用拷贝构造函数
    vector<int> vint5(vint3);
    vector<char> vchar5(vchar3);
    vector<string> vstring5(vstring3);
    //第六种：赋值运算符的重载
    vector<int> vint6 = vint3;
    vector<char> vchar6 = vchar3;
    vector<string> vstring6 = vstring3;
    
    //迭代器定义，正向和反向迭代器
    //四种迭代器：begin（）、end（）、rbegin（）、rend（）
    vector<int>::iterator itini = vint6.begin();
    vector<char>::iterator itchar = vchar6.begin();
    vector<string>::iterator itstring = vstring6.begin();
    itini =vint6.end();
    itchar = vchar.end();
    itstring=vstring.end();
    vector<int>::reverse_iterator ritint =vint6.rbegin();
    vector<char>::reverse_iterator ritchar = vchar.rbegin();
    vector<string>::reverse_iterator ritstring=vstring.rbegin();
    ritint = vint6.rend();
    ritchar = vchar6.rend();
    ritstring=vstring.rend();
    
    //const常量正向d和反向迭代器
    vector<int>::const_iterator citint=vint6.cbegin();
    vector<char>::const_iterator citchar=vchar6.cbegin();
    vector<string>::const_iterator citstring=vstring6.cbegin();
    citint=vint6.cend();
    citchar=vchar6.cend();
    citstring=vstring.cend();
    vector<int>::const_reverse_iterator critint;
    vector<char>::const_reverse_iterator critchar;
    vector<string>::const_reverse_iterator critstring;
    critint=vint6.crbegin();
    critchar=vchar6.crbegin();
    critstring=vstring6.crbegin();
    critint=vint6.crend();
    critchar=vchar6.crend();
    critstring=vstring6.crend();
    //注意区分一下四个
    vector<int> iVec(5,0);
    vector<int>::iterator itint = iVec.begin();//普通迭代器
    vector<int>::const_iterator itint1 = iVec.begin();//常量迭代器即不能用该迭代器修改所指向的e的对象
    const vector<int>::iterator itint2 = iVec.begin();//常量迭代型不能改变迭代器所指向的对象即itint2++是不允许的
    vector<int>::iterator const itint3 = iVec.begin();//常量型迭代不能改变迭代器指向的对象即itint3++是不允许的
    
    //获取vector的大小size() resize() capacity() reserve()函数
    vector<int> test(5,1);
    vector<int>::iterator it_test;
    cout<<"获取test容器的元素个数"<<test.size()<<endl;//指当前容器中存储的元素的个数，可以理解为给容器分配的内存的大小
    cout<<"获取test容器的容量"<<test.capacity()<<endl;//容器在分配新的存储空间之前能存储的元素总数
    cout<<"获取test容器的最大存储，但实际到不了"<<test.max_size()<<endl;
    //更改容器的大小
    test.resize(1);//设置大小，可以开辟出更多的空间，当参数小于时就销毁空间
    test.reserve(test.capacity()+1);
    cout<<"after test.resize(1),the test.size() is "<<test.size()<<endl;
    cout<<"after test.resize(1),the test contains : ";
    it_test = test.begin();
    while(it_test != test.end()){
        cout<<*it_test<<" ";
        it_test++;
    }
    cout<<endl;
    test.resize(10, 2);//如果10大于容器中元素的数目，则在容器的末尾进行拓展，拓展为第二个参数的副本
    cout<<"after test.resize(10,2),the test.size() is "<<test.size()<<endl;
    cout<<"after test.resize(10,2),the test contains : ";
    it_test = test.begin();
    while(it_test != test.end()){
        cout<<*it_test<<" ";
        it_test++;
    }
    cout<<endl;
    
    
    
    //vector的数据操作
    
    //关于元素存取的函数
    //operator[] 既重载[]使其类似于数组元素的操纵，实现随机访问
    //test is [1 2 2 2 2 2 2 2 2 2]
    cout<<test.at(1)<<endl;//类似于[]的作用，只是是一个函数行形式
    cout<<test.front()<<endl;//显示存在的第一个元素
    cout<<test.back()<<endl;//显示存在的最后一个元素
    int* p = test.data();//取到了一个指向顺序表的一个指针
    //修改动作函数
    vector<int>::iterator it = test.begin();
    //test.assign(arr,arr+3);//assign替换函数可以替换一个对象的区间或者一个同类型的数组
    test.push_back(4);//尾插，并没有头插
    test.pop_back();//尾删
    test.insert(it,5);//插入指定位置
    test.erase(it);//删除指定位置
    //test.swap(test1);//交换函数，将两个对象进行交换
    test.clear();//清空整个顺序表
    vector<int>::iterator it2=test.emplace(it,5);//类似于insert但是会返回新插入元的迭代器
    test.emplace_back(10);//类似于尾插

    return 0;
}
