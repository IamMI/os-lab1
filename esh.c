#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>

#include <errno.h>
#include <time.h>
#include <sys/reg.h>
#include <sys/user.h>
#include <sys/syscall.h>
#include <stdbool.h>
#include <setjmp.h>
#include <signal.h>

//
// You should use the following functions to print information
// Do not modify these functions
//

void print_prompt() {
    printf("esh > ");
    fflush(stdout);
}

void print_invalid_syntax() {
    printf("Invalid Syntax\n");
    fflush(stdout);
}

void print_command_not_found() {
    printf("Command Not Found\n");
    fflush(stdout);
}

void print_execution_error() {
    printf("Execution Error\n");
    fflush(stdout);
}

void print_blocked_syscall(char* syscall_name, int count, ...) {
    va_list args;
    va_start(args, count);
    printf("Blocked Syscall: %s ", syscall_name);
    for (int i = 0; i < count; i++) {
        char* arg = va_arg(args, char*);
        printf("%s ", arg);
    }
    printf("\n");
    fflush(stdout);
}

//
// My content
//

// Variable
size_t MAXLINE=50;
enum ERROR
{
    SYNTAXINVALID=0,
    COMMANDNOTFOUND,
    EXECERROR,
    SYSCALLBLOCK,
};
enum INNERCMD
{
    CD=0,
    EXIT,
    EXPORT,
    ENV,
};
enum CHILDRETURN
{
    ENDUP=0,
    MATCHMISS=1,
    ARGERROR=2,
    MEANINGLESS=3,
    RUNNINGERROR=4, 
    INVALIDARR=5,   
};
const char version[10]="IamMI.v1";
// Environment variables
#define MAX_VARS 100
typedef struct {
    char name[64];
    char value[256];
} EnvVar;
EnvVar my_env_vars[MAX_VARS];
int var_count = 0;

// Data type
enum DataType
{
    INT=0,
    STRING,
    ADDR,
};


// Syscall Rule
#define MAX_RULES 100
typedef struct {
    int arg_index;          
    char arg_value_str[256]; 
    long arg_value_int;     
    int is_string;  
} SyscallArgs;

typedef struct {
    char syscall_name[32];  
    int args_count;
    SyscallArgs args[6];
} SyscallRule;

typedef struct {
    SyscallRule rules[MAX_RULES];
    int rule_count;
} RuleSet;

struct syscall_entry {
    const char* name;
    int number;
    int paramNum;
    int paramType[6];
};
struct syscall_entry syscall_table[] = {
    {"read", SYS_read, 3, {INT, STRING, INT}},
    {"write", SYS_write, 3, {INT, STRING, INT}},
    {"open", SYS_open, 3, {STRING, INT, INT}},
    {"mmap", SYS_mmap, 6, {ADDR, INT, INT, INT, INT, INT}},
    {"pipe", SYS_pipe, 1, {ADDR}},
    {"sched_yield", SYS_sched_yield, 0, {}},
    {"dup", SYS_dup, 1, {INT}},
    {"clone", SYS_clone, 5, {ADDR, ADDR, INT, ADDR, ADDR}},
    {"fork", SYS_fork, 0, {}},
    {"execve", SYS_execve, 3, {STRING, ADDR, ADDR}},
    {"mkdir", SYS_mkdir, 2, {STRING, INT}},
    {"chmod", SYS_chmod, 2, {STRING, INT}},
    {NULL, -1, -1, {}},
};


//
// Function
//

// Basic utils
void trim(char *str) {
    int start = 0, end = strlen(str) - 1;
    while (isspace((unsigned char)str[start]) && start<=strlen(str) - 1) start++;
    while (end >= 0 && isspace((unsigned char)str[end])) end--;
    
    if(start>end){
        str[0] = '\0';
    }
    else{
        str[end + 1] = '\0';
        memmove(str, str + start, end - start + 2);
    }
}

void sigpipeHandler(int signum) {
    printf("hello\n");
    if (signum == SIGPIPE) {
        printf("Received SIGPIPE signal!\n");
    }
}

// Syscall rule
int loadRules(char* filename, RuleSet* globalRule) {
    globalRule->rule_count = 0;
    FILE* fp = fopen(filename, "r");
    if (!fp) {
        return -1;
    }
    
    char line[512];
    int flag = 0;
    while (fgets(line, sizeof(line), fp)) {
        trim(line);
        if (line[0] == '\0' || line[0] == '#') continue;

        SyscallRule rule;
        memset(&rule, 0, sizeof(rule));

        // Format: deny:write arg0=xxx
        char* syscall_part = strtok(line, " ");
        char* arg_part = strtok(NULL, "#"); 

        if (!syscall_part) continue;

        if (strncmp(syscall_part, "deny:", 5) != 0) continue;

        strcpy(rule.syscall_name, syscall_part + 5);
        trim(rule.syscall_name);

        
        if(arg_part){
            trim(arg_part);
            // Divide
            char *arg = strtok(arg_part, " ");
            int count = 0;
            while (arg != NULL) {
                trim(arg);
                if (strncmp(arg, "arg", 3) == 0) {
                    sscanf(arg, "arg%d=%s", &rule.args[count].arg_index, rule.args[count].arg_value_str);
                    trim(rule.args[count].arg_value_str);

                    if (rule.args[count].arg_value_str[0] == '"' || rule.args[count].arg_value_str[0] == '\'') {
                        rule.args[count].is_string = 1;
                        size_t len = strlen(rule.args[count].arg_value_str);
                        if (rule.args[count].arg_value_str[len - 1] == '"' || rule.args[count].arg_value_str[len - 1] == '\'')
                            rule.args[count].arg_value_str[len - 1] = '\0';
                        memmove(rule.args[count].arg_value_str, rule.args[count].arg_value_str + 1, len - 1);
                    } else {
                        rule.args[count].is_string = 0;
                        rule.args[count].arg_value_int = atol(rule.args[count].arg_value_str);
                    }
                    count ++;
                }
                else continue;
                arg = strtok(NULL, " ");
            }
            rule.args_count = count;
        }
        else{
            rule.args_count = 0;
        }
        
        if (globalRule->rule_count < MAX_RULES) {
            globalRule->rules[globalRule->rule_count++] = rule;
        }
    }

    fclose(fp);

    return 0;
}

int getSyscallNumber(const char* name) {
    for (int i = 0; syscall_table[i].name != NULL; i++) {
        if (strcmp(name, syscall_table[i].name) == 0) {
            return syscall_table[i].number;
        }
    }
    return -1;
}

const char* getSyscallName(int num){
    for (int i = 0; syscall_table[i].name != NULL; i++) {
        if (num == syscall_table[i].number) {
            return syscall_table[i].name;
        }
    }
    return NULL;
}

int getSyscallCount(int num){
    for (int i = 0; syscall_table[i].name != NULL; i++) {
        if (num == syscall_table[i].number) {
            return syscall_table[i].paramNum;
        }
    }
    return -1;
}

int *getSyscallType(const char* name){
    for (int i = 0; syscall_table[i].name != NULL; i++) {
        if (strcmp(name, syscall_table[i].name) == 0) {
            return syscall_table[i].paramType;
        }
    }
    return NULL;
}

unsigned long getRegisterArg(int argIndex, struct user_regs_struct regs) {
    switch(argIndex) {
        case 0:
            return regs.rdi;
        case 1:
            return regs.rsi;
        case 2:
            return regs.rdx;
        case 3:
            return regs.r10;
        case 4:
            return regs.r8;
        case 5:
            return regs.r9;
        default:
            return -1;
    }
}

char *readStringFromPid(pid_t pid, unsigned long addr) {
    char *str = malloc(4096); 
    int i = 0;
    long word;

    while (1) {
        errno = 0;
        word = ptrace(PTRACE_PEEKDATA, pid, addr + i, NULL);
        if (errno != 0) break;

        memcpy(str + i, &word, sizeof(word));

        if (memchr(&word, 0, sizeof(word)) != NULL) break;

        i += sizeof(word);
    }

    return str;
}

// Error Process
char* formatArg(pid_t pid, unsigned long val, int type) {
    char* result = malloc(50);
    switch(type){
        case INT: 
            sprintf(result, "%lu", val);
            break;
        case STRING:
            sprintf(result, "\"%s\"", readStringFromPid(pid, val));
            break;
        case ADDR:
            sprintf(result, "0x%lx", val);
            break;
        default:
            break;
    }

    return result;
}

void dispatchSyscallArgs(const char* syscall_name, struct user_regs_struct regs, int count, pid_t pid) {
    int* dataType = getSyscallType(syscall_name);

    char* args[6];
    switch (count) {
        case 6:
            args[5] = formatArg(pid, regs.r9, dataType[5]);
        case 5:
            args[4] = formatArg(pid, regs.r8, dataType[4]);
        case 4:
            args[3] = formatArg(pid, regs.r10, dataType[3]);
        case 3:
            args[2] = formatArg(pid, regs.rdx, dataType[2]);
        case 2:
            args[1] = formatArg(pid, regs.rsi, dataType[1]);
        case 1:
            args[0] = formatArg(pid, regs.rdi, dataType[0]);
        case 0:
            break;
        default:
            printf("dispatchSyscallArgs error!\n");
            return;
    }

    
    switch (count) {
        case 0:
            print_blocked_syscall((char*)syscall_name, 0); break;
        case 1:
            print_blocked_syscall((char*)syscall_name, 1, args[0]); break;
        case 2:
            print_blocked_syscall((char*)syscall_name, 2, args[0], args[1]); break;
        case 3:
            print_blocked_syscall((char*)syscall_name, 3, args[0], args[1], args[2]); break;
        case 4:
            print_blocked_syscall((char*)syscall_name, 4, args[0], args[1], args[2], args[3]); break;
        case 5:
            print_blocked_syscall((char*)syscall_name, 5, args[0], args[1], args[2], args[3], args[4]); break;
        case 6:
            print_blocked_syscall((char*)syscall_name, 6, args[0], args[1], args[2], args[3], args[4], args[5]); break;
    }

    for (int i = 0; i < count; ++i) {
        free(args[i]);
    }
}

void errorProcess(char* pos,enum ERROR error,...)
{
    // 
    //  To process all error
    //
    // printf("Sometime catch error: %s!\n", pos);
    switch(error){
        case SYNTAXINVALID:
            print_invalid_syntax();
            break;
        case COMMANDNOTFOUND:
            print_command_not_found();
            break;
        case EXECERROR:
            print_execution_error();
            break;
        case SYSCALLBLOCK: {
            va_list args;
            va_start(args, error);
            char* syscall_name = va_arg(args, char*);
            int count = va_arg(args, int);
            struct user_regs_struct regs = va_arg(args, struct user_regs_struct);
            pid_t pid = va_arg(args, pid_t);

            dispatchSyscallArgs(syscall_name, regs, count, pid);
            va_end(args);
            break;
        }
        default:
            // Left for explore
            break;
    }
}

int extractCmds(char *input, char **commands, int *count) {
    // 
    //  Because pipe is prior to redirection, thus extract cmds aside pipe 
    //  Extract meta-cmd and trim it 
    //
    char *token = input;
    int i = 0;

    if(*count>1)
        while (token) {
            char *pipe_pos = strchr(token, '|');
            if (pipe_pos) {
                // Intermediate cmd
                *pipe_pos = '\0'; 
                commands[i] = strdup(token);
                if(strlen(commands[i])==0){
                    // Consective pipeline
                    return -2;
                }
                trim(commands[i]);
                if(strlen(commands[i])==0){
                    // Blank cmd
                    return -1;
                }
                token = pipe_pos + 1;
            } else {
                // last cmd
                commands[i] = strdup(token);
                trim(commands[i]);
                if(strlen(commands[i])==0){
                    // Blank cmd
                    return -1;
                }
                break;
            }
            i++;
        }
    else{
        // Only one cmd
        commands[i] = strdup(token);
        trim(commands[i]);
        if(strlen(commands[i])==0){
            // Blank cmd
            *count = 0;
        }
    }

    return 0;
}

void parseArgs(char *input, char **argv) {
    //
    //  For one cmd, extract cmd and its args
    //
    int argc = 0;
    while (*input) {
        while (isspace(*input)) input++;
        if (*input == '\0') break;
        if (*input == '"' || *input == '\'') {
            char quote = *input++;
            argv[argc++] = input;
            while (*input && *input != quote) input++;
            if (*input) *input++ = '\0'; 
        } else {
            argv[argc++] = input;
            while (*input && !isspace(*input)) input++;
            if (*input) *input++ = '\0'; 
        }
    }
    argv[argc] = NULL;
}

void getDataFromChild(pid_t child, unsigned long addr, char *str, int pathlen) {
    int i = 0;
    long data;

    while (i < pathlen) {
        data = ptrace(PTRACE_PEEKDATA, child, addr + i, NULL);
        if (data == -1 && errno != 0) break;
        memcpy(str + i, &data, sizeof(data));

        if (memchr(&data, 0, sizeof(data)) != NULL) break;  
        i += sizeof(data);
    }

    str[pathlen - 1] = '\0'; 
}

// Innercmd determine
enum INNERCMD innerCmdDeter(char *cmd){
    // cd
    if((strlen(cmd)==2 && !strncmp(cmd, "cd", 2)) || !strncmp(cmd, "cd ", 3)){
        // printf("cmd: cd\n");
        return CD;
    }
    else if((!strncmp(cmd, "exit", 4) && strlen(cmd)==4) || !strncmp(cmd, "exit ", 5)){
        // printf("cmd: exit\n");
        return EXIT;
    }
    else if(!strncmp(cmd, "export ", 7) || (strlen(cmd)==6 && !strncmp(cmd, "export", 6))){
        // printf("cmd: export\n");
        return EXPORT;
    }
    // else if(!strncmp(cmd, "env", 3) && strlen(cmd)==3){
    //     // printf("cmd: env\n");
    //     return ENV;
    // }
    else{
        return -1;
    }
}

// Inner cmds
void cd(char* input){
    // Execute cd cmd

    // 1. extract path
    char* path = (input+2);
    trim(path);
    if(!strncmp(path, "~", 1)){
        // "~" -> cwd
        char newpath[1024];
        strcpy(newpath, my_env_vars[1].value);
        strcat(newpath, path+1);
        path = newpath;
    }
    if(!strncmp(path, "-", 1)){
        // "-" -> oldpwd
        char newpath[1024];
        strcpy(newpath, my_env_vars[3].value);
        strcat(newpath, path+1);
        path = newpath;
    }
    
    // 2. change workdir
    if(chdir(path)){
        // execute error
        errorProcess("executing cd command catch error!", SYNTAXINVALID);
    }
    else{
        // update pwd and oldpwd
        strcpy(my_env_vars[3].value, my_env_vars[2].value);
        getcwd(my_env_vars[2].value, sizeof(my_env_vars[2].value));
    }
}

void export(char* input){
    // Execute export

    // 1.extract name and value
    char* c = input+6;
    char *pos = strchr(c, '=');
    char* envName, *envValue;
    char spaceKey=' ';
    envValue = &spaceKey;


    if (pos) {
        envValue = strdup(pos+1);
        *pos = '\0'; 
        envName = strdup(c);
        trim(envName);
        trim(envValue);
    } 
    else{
        // clean
        trim(c);
        if(!strlen(c)){
            errorProcess("export space", SYNTAXINVALID);
            return;
        }

        envName = strdup(c);
        trim(envName);
    }

    // 3. set env value
    setenv(envName, envValue, 1);
    // 4. Store 
    for (int i = 0; i < var_count; i++) {
        if (strcmp(my_env_vars[i].name, envName) == 0) {
            strcpy(my_env_vars[i].value, envValue);
            return;
        }
    }
    if (var_count < MAX_VARS) {
        strcpy(my_env_vars[var_count].name, envName);
        strcpy(my_env_vars[var_count].value, envValue);
        var_count++;
    }
}

void env(char* input){
    // Execute env
    for(int index=0; index<var_count; index++){
        printf("%s=%s\n", my_env_vars[index].name, my_env_vars[index].value);
    }
}

// Parse child return
int waitpidTimeout(pid_t pid, int* status, int timeout){
    time_t start_time = time(NULL);
    while (1) {
        pid_t result = waitpid(pid, status, WNOHANG);
        if (result==pid) {
            return 0;
        } else if (result==-1) {
            errorProcess(" ", EXECERROR);
            return -1;
        }

        if (time(NULL) - start_time >= timeout) {
            printf("Timeout waiting for child process %d. Killing it.\n", pid);
            kill(pid, SIGKILL); 
            return -1;
        }
        usleep(100000); 
    }
    return 0;
}

int syscallBlock(pid_t pid, RuleSet* globalRule){
    //
    //  Parse child for syscall
    //
    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, pid, NULL, &regs);
    
    // Traverse globalRule
    for(int index=0; index<globalRule->rule_count; index++){
        int syscallNumber = getSyscallNumber(globalRule->rules[index].syscall_name);

        if (regs.orig_rax == syscallNumber) {
            if(globalRule->rules[index].args_count==0){
                // Shut down
                return 1;
            }
            else{
                int flag=0;
                for(int i=0; i<globalRule->rules[index].args_count; i++){
                    // 1. obtain user input string addr
                    unsigned long addr = getRegisterArg(globalRule->rules[index].args[i].arg_index, regs);
                    if(addr == -1){
                        errorProcess("syscallBlock, addr fail", EXECERROR);
                        return 1;
                    }
                    
                    // 2. obtain user input args
                    if(globalRule->rules[index].args[i].is_string){
                        // 2.1 read string from regs
                        char* string = readStringFromPid(pid, addr);

                        if(string != NULL)
                            if(strlen(globalRule->rules[index].args[i].arg_value_str)==strlen(string))
                                // 3. compare
                                if(!strncmp(string, globalRule->rules[index].args[i].arg_value_str, strlen(globalRule->rules[index].args[i].arg_value_str))){
                                    free(string);
                                    flag += 1;
                                    continue;
                                }
                        free(string);
                    }
                    else{
                        if(addr==globalRule->rules[index].args[i].arg_value_int){
                            // Shut down
                            flag += 1;
                        }
                    }
                }
                if(flag == globalRule->rules[index].args_count){
                    return 1;
                }
            }
        }
    }
    return 0;
}

void ParseChildReturn(pid_t* pids, int count, bool sandbox, RuleSet* globalRule){
    int status;
    int finished = 0;
    while (finished < count) {
        pid_t pid = waitpid(-1, &status, __WALL);
        if (pid == -1) break;

        // Exit
        if (WIFEXITED(status)) {
            finished++;
            // Exit code
            int exit_code = WEXITSTATUS(status);
            switch(exit_code){
                case ENDUP:
                    // cmd end up
                    break;
                case MATCHMISS:
                    // cmd match miss
                    errorProcess("Cmds match miss!", EXECERROR);
                    break;
                case ARGERROR:
                    // cmd's args illegal
                    errorProcess("Cmds input args illegal!", EXECERROR);
                    break;
                case MEANINGLESS:
                    // cmd non-executable
                    errorProcess("Cmds non-executable!", COMMANDNOTFOUND);
                    break;
                case RUNNINGERROR:
                    errorProcess("Cmds running error!", EXECERROR);
                    break;
                case INVALIDARR:
                    errorProcess(" ", SYNTAXINVALID);
                    break;
                default:
                    errorProcess("New error occur at externalCmd!", EXECERROR);
                    break;
            }
            continue;
        }

        // Syscall
        if(sandbox){
            if (WIFSTOPPED(status)) {
                if(syscallBlock(pid, globalRule)){
                    struct user_regs_struct regs;
                    ptrace(PTRACE_GETREGS, pid, NULL, &regs);
                    errorProcess("Syscall block", SYSCALLBLOCK, getSyscallName(regs.orig_rax), getSyscallCount(regs.orig_rax), regs, pid);
                    kill(pid, SIGKILL);
                    finished++;
                    continue;
                }
                ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
            }
        }
    }
}

// External cmds
void externalCmd(char* cmd){
    //
    //  Carry out cmd
    //

    // 1. Clean cmd    
    trim(cmd);
    // 2. Avoid inner instruction
    if(innerCmdDeter(cmd)!=-1) exit(RUNNINGERROR);
    // 3. Find out redirection
    char* redirects[8] ;
    int redirect_count = 0;
    int in_quote = 0;
    char quote_char = '\0';

    for (char* p = cmd; *p; ++p) {
        if (*p == '\'' || *p == '"') {
            if(in_quote == 0){
                in_quote = 1;
                quote_char = *p;
            } 
            else if(*p == quote_char){
                in_quote = 0;
            }
        } 
        else if(*p == '>' && in_quote == 0){
            if(*(p+1)=='>'){
                // ">>" -> Invalid syntax
                exit(INVALIDARR);
            }
            // ">" -> redirect
            // redirect_pos = p;
            // break;
            *p = '\0';  // 分隔 cmd
            char* filename = p + 1;
            redirects[redirect_count++] = filename;
        }
        else if(*p == '<' && in_quote == 0){
            // "<" -> Invalid syntax
            exit(ARGERROR);
        }
    }
    
    char* argv[32];
    int fd = -1;
    for (int i = 0; i < redirect_count; ++i) {
        trim(redirects[i]);
        int tmpfd = open(redirects[i], O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (tmpfd < 0) {
            exit(RUNNINGERROR);
        }
        if (i == redirect_count - 1) {
            dup2(tmpfd, STDOUT_FILENO);
        }
        close(tmpfd); 
    }
    
    parseArgs(cmd, argv); 

    // Signal process
    // if (signal(SIGPIPE, sigpipeHandler) == SIG_ERR) {
    //     exit(RUNNINGERROR);
    // }
    
    // Run code
    if (strcmp(argv[0], "env") == 0 && argv[1] == NULL) {
        // env
        env(NULL);
        exit(ENDUP);
    } 
    else{
        if (execvp(argv[0], argv) == -1) {
            // Command not found
            exit(MEANINGLESS);
        }
    }
    exit(ENDUP);
}

void externalCmds(char** cmds, int count, bool sandbox, ...){
    //
    //  Fork progress to execute cmds
    //  Responds for error processing 
    //

    // sandbox detection
    RuleSet* globalRule;
    if(sandbox){
        va_list args;
        va_start(args, sandbox);
        globalRule = va_arg(args, RuleSet*);
        va_end(args);
    }
    
    int i;
    int pipefd[2*(count-1)];  
    int pids[count];
    // Create pipe
    for (i=0; i<count-1; i++) {
        if (pipe(pipefd + 2*i) < 0) {
            perror("pipe");
            exit(EXIT_FAILURE);
        }
    }
    // Fork
    for (i=0; i<count; i++) {
        pid_t pid = fork();
        if (pid < 0) {
            errorProcess("ExternalCmds catch error at fork!", EXECERROR);
        }
        
        if (pid == 0) {
            // Child
            // 1. bind pipe with stdout and stdin
            if (i!=0) {
                if (dup2(pipefd[(i-1)*2], STDIN_FILENO) < 0) {
                    errorProcess("ExternalCmds catch error at pipe!", EXECERROR);
                }
            }
            if (i!=count-1) {
                if (dup2(pipefd[i*2+1], STDOUT_FILENO) < 0) {
                    errorProcess("ExternalCmds catch error at pipe!", EXECERROR);
                }
            }
            // 2. close all pipes
            for (int j=0; j<2*(count-1); j++) {
                close(pipefd[j]);
            }
            // 3. ptrace
            if(sandbox){
                ptrace(PTRACE_TRACEME, 0, NULL, NULL);
                kill(getpid(), SIGSTOP); 
            }
            // 4. execute cmd
            externalCmd(cmds[i]);
            // 5. endup
            exit(ENDUP);
        }
        else{
            // Parent
            pids[i] = pid;
        }
    }
    // Parent
    // 1. close all pipes
    for (i=0; i<2*(count-1); i++) {
        close(pipefd[i]);
    }
    // 2. wait for all child and parse their syscall and exit code
    ParseChildReturn(pids, count, sandbox, globalRule);

}   

// Cmds analysis
void commandAnalysis(char* input)
{
    //
    //  Analyse input command, carry out and process error
    //
    
    trim(input);
    // Sandbox detection
    bool sandbox = false;
    RuleSet* globalRule = malloc(sizeof(RuleSet));

    if(!strncmp(input, "sandbox ", 8)){
        // Extract rules
        input += 8;
        char* space = strchr(input, ' ');
        if(!*space){
            errorProcess("Input error", SYNTAXINVALID);
            return ;
        }
        *space = '\0';
        char* rule = input;
        input = space+1;
        // Load rules
        if(loadRules(rule, globalRule)==-1){
            errorProcess("loadRule error", EXECERROR);
            return;
        }
        sandbox = true;
    }

    // Determine how many commands aside pipes exist
    char** commands;
    int count=1;
    int state = 0;
    for (char *p = input; *p; p++) {
        if (*p == '\'' || *p == '\"'){
            if (state==1) state=0;
            else state=1;
        }
        if (*p == '|' && state==0){
            count++;
        }
    }

    // Allocate space
    commands = (char **)malloc(count * sizeof(char *));
    if (!commands) {
        errorProcess("commandAnalysis", EXECERROR);
        exit(1);
    }

    // Extract commands aside pipes
    int exitcode = extractCmds(input, commands, &count);
    if(exitcode == -1){
        // Extract space-key
        errorProcess("extractCmds, catch space-key!", EXECERROR);
        return;
    }
    else if(exitcode == -2){
        // Extract consecutive pipeline
        errorProcess("extractCmds, catch consecutive pipeline!", SYNTAXINVALID);
        return;
    }

    // For any cmd, fork a new progress and execute it
    if(count==0){
        // Blank input, ignore

    }
    else if(count==1){
        // Determine whether inner cmd or not
        switch(innerCmdDeter(commands[0])){
            case CD:
                cd(commands[0]);
                break;
            case EXIT:
                exit(0);
                break;
            case EXPORT:
                export(commands[0]);
                break;
            default:
                if(sandbox)
                    externalCmds(commands, count, true, globalRule);
                else 
                    externalCmds(commands, count, false);
                break;
        }
    }
    else{
        if(sandbox)
            externalCmds(commands, count, true, globalRule);
        else 
            externalCmds(commands, count, false);
    }

    free(globalRule);
}

int main(void) 
{   
    // Initial
    char home[1024];
    if (getcwd(home, sizeof(home)) == NULL) {
        errorProcess("getcwd catch error!", EXECERROR);
        return EXIT_FAILURE;
    } 
    // Environment
    strcpy(my_env_vars[0].name, "PATH");
    strcpy(my_env_vars[0].value, "/bin");
    strcpy(my_env_vars[1].name, "HOME");
    strcpy(my_env_vars[1].value, home);
    strcpy(my_env_vars[2].name, "PWD");
    strcpy(my_env_vars[2].value, home);    
    strcpy(my_env_vars[3].name, "OLDPWD");
    strcpy(my_env_vars[3].value, home);
    strcpy(my_env_vars[4].name, "LANG");
    strcpy(my_env_vars[4].value, "en_US.UTF-8");
    strcpy(my_env_vars[5].name, "ESH_VERSION");
    strcpy(my_env_vars[5].value, version);   
    var_count = 6;


    while(1) {
        print_prompt();
        // Receive input
        char *input=(char*)malloc(50);
        // input = "hello | good | bye";
        if(getline(&input,&MAXLINE,stdin)==-1){
            // Ctrl+D
            exit(0);
        }
        
        // Analyse and execute
        commandAnalysis(input);
    }
}
