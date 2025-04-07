1. One cmd
    1.1 Inner cmd
    1.2 External cmd

2. Multi-cmds with pipe
    2.1 cmd1 | cmd2
    2.2 cmd1 | cmd2 | cmd3 
    2.3 inner-cmd | cmd1
    2.4 cmd1 | inner-cmd
    2.5 cmd1 | inner-cmd | cmd2
    
3. Redirection
    3.1 cmd1 > file
    3.2 cmd1 | cmd2 > file
    3.3 cmd1 > file | cmd2
    3.4 cmd1 > file | inner-cmd

        - "echo hello > out.txt > another.txt"不支持连续重定向
        


4. Error
    4.1 syntax error

5. Sandbox
    5.1 sandbox cmd1 
    5.2 sandbox cmd1 | cmd2
    5.3 sandbox cmd1 > file | cmd2
    5.4 sandbox cmd1 | cmd2 > file


        - 为什么执行到一半，globalRule会出现那么长的count？
        - 代码无法处理./a.out，因为前面有./
        - 代码还没有处理好syscall block的情况