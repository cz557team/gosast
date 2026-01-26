/*
 * Path Traversal (CWE-22) Test Cases
 *
 * This file contains various path traversal vulnerability scenarios
 * for testing the PathTraversalDetector.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// ============================================================================
// VULNERABLE CASES
// ============================================================================

// VULN-1: Static "../" pattern in hardcoded string
void vuln_static_pattern() {
    FILE* f = fopen("../../etc/passwd", "r");  // CWE-22: Static traversal pattern
    if (f) {
        char buffer[1024];
        fgets(buffer, sizeof(buffer), f);
        fclose(f);
    }
}

// VULN-2: Static "..\\ pattern for Windows
void vuln_static_pattern_windows() {
    FILE* f = fopen("..\\..\\windows\\system32\\config\\sam", "r");  // CWE-22: Windows traversal
    if (f) fclose(f);
}

// VULN-3: URL-encoded traversal pattern
void vuln_url_encoded() {
    char* path = "%2e%2e%2f%2e%2e%2fetc%2fpasswd";  // CWE-22: URL-encoded ../
    FILE* f = fopen(path, "r");
    if (f) fclose(f);
}

// VULN-4: User input without validation
void vuln_user_input_direct() {
    char filename[256];
    printf("Enter filename: ");
    // gets() is dangerous, but we're testing path traversal
    gets(filename);  // User could input: "../../etc/passwd"

    FILE* f = fopen(filename, "r");  // CWE-22: No validation
    if (f) fclose(f);
}

// VULN-5: User input via scanf
void vuln_user_input_scanf() {
    char filename[256];
    scanf("%255s", filename);  // User input

    FILE* f = fopen(filename, "r");  // CWE-22: No validation
    if (f) fclose(f);
}

// VULN-6: String concatenation with user input
void vuln_concatenation(char* user_file) {
    char path[256];
    strcpy(path, "/var/www/files/");
    strcat(path, user_file);  // CWE-22: user_file could be "../../etc/passwd"

    FILE* f = fopen(path, "r");
    if (f) fclose(f);
}

// VULN-7: sprintf with user input
void vuln_sprintf(char* user_file) {
    char path[256];
    sprintf(path, "/var/www/files/%s", user_file);  // CWE-22: No validation

    FILE* f = fopen(path, "r");
    if (f) fclose(f);
}

// VULN-8: snprintf still vulnerable if input is not validated
void vuln_snprintf(char* user_file) {
    char path[256];
    snprintf(path, sizeof(path), "/var/www/files/%s", user_file);  // CWE-22

    FILE* f = fopen(path, "r");
    if (f) fclose(f);
}

// VULN-9: Direct access to sensitive file with absolute path
void vuln_sensitive_path_absolute() {
    FILE* f = fopen("/etc/passwd", "r");  // CWE-22: Access to sensitive file
    if (f) fclose(f);
}

// VULN-10: Access to SSH keys
void vuln_ssh_keys() {
    FILE* f = fopen("/root/.ssh/id_rsa", "r");  // CWE-22: SSH private key
    if (f) fclose(f);
}

// VULN-11: Access to AWS credentials
void vuln_aws_credentials() {
    FILE* f = fopen("/home/user/.aws/credentials", "r");  // CWE-22: AWS credentials
    if (f) fclose(f);
}

// VULN-12: Multiple traversal patterns
void vuln_deep_traversal() {
    FILE* f = fopen("../../../../../../../../etc/passwd", "r");  // CWE-22: Deep traversal
    if (f) fclose(f);
}

// VULN-13: Traversal with subdirectory
void vuln_traversal_with_subdir() {
    FILE* f = fopen("files/../../etc/passwd", "r");  // CWE-22: Mixed path
    if (f) fclose(f);
}

// VULN-14: Using stat with tainted path
void vuln_stat_tainted(char* user_path) {
    struct stat st;
    if (stat(user_path, &st) == 0) {  // CWE-22: stat with user input
        printf("File size: %ld\n", st.st_size);
    }
}

// VULN-15: Using unlink with tainted path
void vuln_unlink_tainted(char* user_path) {
    unlink(user_path);  // CWE-22: Could delete system files
}

// VULN-16: Using opendir with tainted path
void vuln_opendir_tainted(char* user_path) {
    DIR* dir = opendir(user_path);  // CWE-22: Directory traversal
    if (dir) closedir(dir);
}

// VULN-17: Access to .env file
void vuln_env_file() {
    FILE* f = fopen(".env", "r");  // CWE-22: Environment variables
    if (f) fclose(f);
}

// ============================================================================
// SAFE CASES (should NOT trigger)
// ============================================================================

// SAFE-1: Proper validation with strstr check
void safe_with_validation(char* filename) {
    // Check for path traversal patterns
    if (strstr(filename, "..") != NULL) {
        printf("Invalid filename: contains path traversal\n");
        return;
    }

    FILE* f = fopen(filename, "r");
    if (f) fclose(f);
}

// SAFE-2: Using whitelist for allowed files
void safe_with_whitelist(char* filename) {
    const char* allowed[] = {"file1.txt", "file2.txt", "file3.txt"};
    int is_allowed = 0;

    for (int i = 0; i < 3; i++) {
        if (strcmp(filename, allowed[i]) == 0) {
            is_allowed = 1;
            break;
        }
    }

    if (!is_allowed) {
        printf("File not allowed\n");
        return;
    }

    FILE* f = fopen(filename, "r");
    if (f) fclose(f);
}

// SAFE-3: Using realpath for normalization
void safe_with_realpath(char* filename) {
    char resolved[PATH_MAX];
    if (realpath(filename, resolved) == NULL) {
        printf("Invalid path\n");
        return;
    }

    // Check if resolved path is within allowed directory
    const char* base_dir = "/var/www/files";
    if (strncmp(resolved, base_dir, strlen(base_dir)) != 0) {
        printf("Path outside allowed directory\n");
        return;
    }

    FILE* f = fopen(resolved, "r");
    if (f) fclose(f);
}

// SAFE-4: Hardcoded safe path (not sensitive)
void safe_hardcoded_safe_path() {
    FILE* f = fopen("/var/www/html/index.html", "r");  // Safe: non-sensitive file
    if (f) fclose(f);
}

// SAFE-5: Static file without traversal patterns
void safe_static_filename() {
    FILE* f = fopen("config.json", "r");  // Safe: no traversal patterns
    if (f) fclose(f);
}

// SAFE-6: Local include without traversal
void safe_local_include() {
    FILE* f = fopen("include/header.h", "r");  // Safe: local file
    if (f) fclose(f);
}

// ============================================================================
// EDGE CASES
// ============================================================================

// EDGE-1: Traversal pattern in comment (should NOT trigger)
void edge_traversal_in_comment() {
    // This is a comment with ../../etc/passwd pattern
    FILE* f = fopen("config.txt", "r");
    if (f) fclose(f);
}

// EDGE-2: Traversal in string but not used in file operation
void edge_traversal_not_used() {
    char* msg = "This is not a path: ../../etc/passwd";
    printf("%s\n", msg);
}

// EDGE-3: Empty string
void edge_empty_path() {
    FILE* f = fopen("", "r");
    if (f) fclose(f);
}

// EDGE-4: Relative path without traversal
void edge_relative_safe() {
    FILE* f = fopen("../include/header.h", "r");  // Safe: no sensitive file access
    if (f) fclose(f);
}

// ============================================================================
// MAIN FOR TESTING
// ============================================================================

int main() {
    // Test vulnerable cases
    vuln_static_pattern();
    vuln_static_pattern_windows();
    vuln_url_encoded();

    // Test safe cases
    safe_hardcoded_safe_path();
    safe_static_filename();

    return 0;
}
