This part codes mainly refer two projects:

1. [bn256](https://github.com/cloudflare/bn256), 主要是基域运算。这个项目的主要问题在于测试太少。后续进行了大量改进：增加测试、减少乘法、常量时间运行的ScalarMult实现、优化的Invert/Sqrt实现、直至替换基础域计算实现。
2. [gmssl sm9](https://github.com/guanzhi/GmSSL/blob/develop/src/sm9_alg.c)，主要是2-4-12塔式扩域（现在实现了1-2-4-12扩域以及1-2-6-12扩域，以及相互转换），以及r-ate等。这个项目的主要问题在于性能没有怎么优化。基于性能考虑，后续r-rate还是参考了bn256的op-ate，并结合sm9的特殊性做了适应性改造。
3. [SM9 precompute pairing per master public key level](https://github.com/emmansun/gmsm/discussions/60)。
4. G1, G2曲线倍点运算预计算。
5. 更加高效的基础域gfP汇编方法实现。
6. 分圆子域上的特殊平方运算实现。
7. Miller运算中，line add/double运算不返回新建对象。
8. Marshal/Unmarshal，select，set的asm实现。
