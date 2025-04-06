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
    RUNNINGERROR=4,
    MEANINGLESS=3,
    ARGERROR=2,
    MATCHMISS=1,
    ENDUP=0,    
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


//
// Function
//

// Error Process
void errorProcess(char* pos,enum ERROR error,...)
{
    // 
    //  To process all error
    //
    printf("Sometime catch error: %s!\n", pos);
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
            print_blocked_syscall(syscall_name, count, args);
            va_end(args);
            break;
        }
        default:
            // Left for explore
            break;
    }
}

// Pipe determine and extract
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
    else if(!strncmp(cmd, "env", 3) && strlen(cmd)==3){
        // printf("cmd: env\n");
        return ENV;
    }
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
        envName = strdup(c);
        trim(envName);
        
    }

    // 2. set env value
    setenv(envName, envValue, 1);
    // 3. Store 
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

void ParseChildReturn(pid_t pid){
    int status;
    if(waitpidTimeout(pid, &status, 3)!=0){
        // Timeout
        errorProcess("waitpid timeout", EXECERROR);
        return;
    }

    if (WIFEXITED(status)) {
        int exit_code = WEXITSTATUS(status);
        switch(exit_code){
            case ENDUP:
                // cmd end up
                break;
            case MATCHMISS:
                // cmd match miss
                break;
            case ARGERROR:
                // cmd's args illegal
                errorProcess("Cmds input args illegal!", SYNTAXINVALID);
                break;
            case MEANINGLESS:
                // cmd non-executable
                errorProcess("Cmds non-executable!", COMMANDNOTFOUND);
                break;
            case RUNNINGERROR:
                errorProcess("Cmds running error!", EXECERROR);
                break;
            default:
                errorProcess("New error occur at externalCmd!", EXECERROR);
                break;
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
    if(innerCmdDeter(cmd)!=-1) exit(ENDUP);
    // 3. Find out redirection
    char* redirect_pos = NULL;
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
                exit(ARGERROR);
            }
            // ">" -> redirect
            redirect_pos = p;
            break;
        }
        else if(*p == '<' && in_quote == 0){
            // "<" -> Invalid syntax
            exit(ARGERROR);
        }
    }

    char* argv[32];
    if (redirect_pos) {
        // 4. Divide
        *redirect_pos = '\0';
        char* filename = redirect_pos + 1;
        trim(cmd);        
        trim(filename);   

        // 5. Open file and redirect
        int fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (fd < 0) {
            exit(RUNNINGERROR);
        }
        dup2(fd, STDOUT_FILENO);
        close(fd);
    }

    parseArgs(cmd, argv);  
    if (execvp(argv[0], argv) == -1) {
        exit(MEANINGLESS);
    }
    exit(ENDUP);
}

void externalCmds(char** cmds, int count){
    //
    //  Fork progress to execute cmds
    //  Responds for error processing 
    //

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
            // 3. execute cmd
            externalCmd(cmds[i]);
            // 4. endup
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
    // 2. wait for all child and parse their exit_code
    for(i=0; i<count; i++){
        ParseChildReturn(pids[i]);
    }

}   

// Cmds analysis
void commandAnalysis(char* input)
{
    //
    //  Analyse input command, carry out and process error
    //
    
    // Determine how many commands aside pipes exist
    char** commands;
    int count=1;
    for (char *p = input; *p; p++) {
        if (*p == '|'){
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
    if(extractCmds(input, commands, &count)==-1){
        // Extract space-key
        errorProcess("extractCmds, catch space-key!", COMMANDNOTFOUND);
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
            case ENV:
                env(commands[0]);
                break;
            default:
                externalCmds(commands, count);
                break;
        }
    }
    else{
        externalCmds(commands, count);
    }
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
        getline(&input,&MAXLINE,stdin);
        // Analyse and execute
        commandAnalysis(input);
        
    }
}
