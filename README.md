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