
{
    input = 0;
    cin >> input;
    if (input == 123456)
        OK;
    else
        FAIL;

}  // 以上代码表示原始的程序逻辑

//下面是被混淆后的代码

// CTD[]包裹的函数表示的表示Compile-time determined编译期运行pass的时候调用，并且确定的
{
    flowkey = CTD[rand()];  //这是我们插入的一个全局变量，初始值为随机值

    input = CTD[0 ^ flowkey] ^ flowkey;  // 这里的0是原来的常量，为了加密立即数0，我们将其改写为0 ^ flowkey，这是在编译期间就能确定的值，在运行期间再次^ flowkey得到原来的值。所有的常量都需要这样处理。
    cin >> input;
}
// 重写if-else结构
// 在进入循环前我们为了让hash函数的输入多样化
// 需要重写循环条件正确条件
// 设原有的if的的条件为Condition，即if (Condition!=0) { OK } else { FAIL }
// 则我们需要将Condition改写为
// Condition ^ flowkey  != 0 ^ flowkey
// 这样可以保证数学上不改变条件的结果
// 这样我们既和flowkey产生了依赖关系，又能在编译期知道CTD[0 ^ flowkey]的值
while (1)
{
    switch (hash(Condition ^ flowkey))
    {
        case CTD[hash(0 ^ flowkey)]:
        {
            // 正确块
            //正确逻辑
            flowkey = CTD[hash(这里随机对flowkey做一些运算)]
        }
        case CTD[hash(rand())]:
        {
            // 垃圾块 ，也可以叫做不可达块
            // 1. 拷贝正确块的代码，并且随机对正确块的代码做随机修改，随机包括增加逻辑和减少逻辑，但是要保证语法正确防止编译出错
            // 2. 修改flowkey为随机值
            flowkey = CTD[hash(这里随机对flowkey做一些运算但是 与 正确块不同)]
        }
            // 这里可以添加更多垃圾块不再赘述
    }
}