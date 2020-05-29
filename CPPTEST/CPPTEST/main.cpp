#include<iostream>
#include <math.h>
using namespace std;
#define pi 3.14

class base{
public:
    virtual void area() = 0;
};


class triangle: public base{
public:
    triangle(float aa, float bb, float cc): a(aa),b(bb),c(cc) {}
    void area(){
        float p = (a + b + c)/2;
        float s = sqrt(p*(p-a)*(p-b)*(p-c));
        cout<< "the triangle's area() is called" << " and the area is " << s << endl;
    }
private:
    float a,b,c;
};

class rectangle: public base{
public:
    rectangle(float aa): a(aa) {}
    void area(){
        cout<< "the rectangle's area() is called"<< " and the area is " << a * a << endl;
    }
private:
    float a;
};

class circle: public base{
public:
    circle(float rr):r(rr){}
    void area(){
        cout<< "the circle's area() is called"<< " and the area is " << pi * r * r << endl;
    }
private:
    float r;
};

int main(){
    base *p = new triangle(3,4,5);
    base *q = new rectangle(3);
    base *t = new circle(3);
    p->area();
    q->area();
    t->area();
    return 0;
}
