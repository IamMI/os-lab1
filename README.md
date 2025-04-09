We ask ChatGPT for generating testing cmds and record error case
    1. "ls | | cat" raise "Command Not Found" instead of "Invalid Syntax" √
    2. "> only" do not raise error √
    3. "cat nonexistentfile.txt " do not raise error √
    4. "ls /root/secret " raise "Invalid Syntax" instead of "Execution Error" √
    5. "rm" do not raise error √
    6. "export " do not raise error "Invalid Syntax" √
    7. "sandbox rule.txt ls" do not raise error when "deny:read" √

        
This part contains vague definitions
    1. "cd " is error or not?
    2. "foo | bar" raise one error or two?
    3. "yes | head -n 5" do not raise error, however, demo raise "Execution Error"
    4. 

Potential error
    1. Divide cmd just using detect '|' may fail sometime
