OSLab1🚀
You could read OSLab1--Shell.pdf for understanding my codeframe!


OJ wrong test:
- "cd a\nls -e\n",
- "ls a b\nls aaa bbb\n",
- "cd a\necho 1|ls|echo 1\nexit\n",
- "ls | \"\"\n",
- "cd a\nls | cd a1\npwd\n",
- "ls | sort | export PATH=/bin:./a\nenv\n",
- "cd a\nls > 1.txt > 2.txt\ncat 1.txt\ncat 2.txt\n",

- "sandbox deny_write_arg01.txt a.out\n",
- "cd a\nsandbox ../deny_write.txt ls | sort\n",
- "sandbox deny_execve.txt ./b/hello\n",
- "sandbox deny_write.txt a.out\n",
- "cd a\nsandbox ../deny_execve_arg0.txt bash -c 'ls | head -n 1'\n",

- "ls | \nexit\n",
- "cd a\necho 1|ls|echo 1\nexit\n",
- "ls | \"\"\n",
- "cd a\nls | cd a1\npwd\n",
- "ls | sort | export PATH=/bin:./a\nenv\n",
- "echo 1 >> 2.txt\ncat 2.txt\n",
- "sandbox deny_write_arg01.txt a.out\n",
- "cd a\nsandbox ../deny_write.txt ls | sort\n",
- "sandbox deny_execve.txt ./b/hello\n",
- "sandbox deny_write.txt a.out\n",
- "cd a\nsandbox ../deny_execve_arg0.txt bash -c 'ls | head -n 1'\n",


- "cd a\necho 1 | ../a.out | echo 1\nexit\n",
- "cd a\n../a.out | echo 1223\nexit\n",
- "cd a\ncd a1 | ls\n",
- "echo 1 >> 2.txt\ncat 2.txt\n",
- "sandbox deny2_write_fork.txt ./a.out\n",
- "sandbox deny_write_arg0.txt ./a.out\n",
- "sandbox deny_write_arg01.txt ./a.out\n",
- "cd a\nsandbox ../deny_write.txt ls | sort\n",
- "cd a\nsandbox ../deny_write.txt ls > 1.txt\ncat 1.txt\nrm 1.txt\n",
- "sandbox deny_execve.txt ./b/hello\n",
- "sandbox deny_write.txt ./a.out\n",
- "cd a\nsandbox ../deny_execve_arg0.txt bash -c 'ls | head -n 1'\n",

- "cd a\necho 1 | ../a.out | echo 1\nexit\n",
- "cd a\n../a.out | echo 1223\nexit\n",
- "cd a\ncd a1 | ls\n",
- "echo 1 >> 2.txt\ncat 2.txt\n",
- "sandbox deny_write_arg01.txt ./a.out\n",
- "cd a\nsandbox ../deny_write.txt ls | sort\n",
- "sandbox deny_write.txt ./a.out\n",
- "cd a\nsandbox ../deny_execve_arg0.txt bash -c 'ls | head -n 1'\n",