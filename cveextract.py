#!/usr/bin/env python3

import os
import re
import subprocess
import shutil
import json
import hashlib
import concurrent.futures
import multiprocessing
from datetime import datetime
from functools import partial
import threading

# Thread-local storage for thread safety
thread_local = threading.local()

def get_cpu_count():
    """Get the number of available CPU cores, leaving one for system operations."""
    cores = max(1, multiprocessing.cpu_count() - 1)
    return cores

def run_command(command):
    """Run a shell command and return its output."""
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=300)
        if result.returncode != 0:
            return ""
        return result.stdout.strip()
    except subprocess.TimeoutExpired:
        print(f"Warning: Command '{command}' timed out after 5 minutes")
        return ""
    except Exception as e:
        print(f"Error running command '{command}': {str(e)}")
        return ""

def extract_security_ids(text):
    """Extract security identifiers (CVE IDs, etc.) from text."""
    # Standard CVE format: CVE-YYYY-NNNNN[NN]
    cve_pattern = re.compile(r'(CVE-\d{4}-\d{4,})')
    
    # Common security-related keywords
    security_patterns = [
        r'\bsecurity\s+fix\b',
        r'\bsecurity\s+issue\b',
        r'\bsecurity\s+vulnerability\b',
        r'\bsecurity\s+bug\b',
        r'\bvulnerability\b',
        r'\bsec-\d+\b',
        r'\bsecurity\s+patch\b',
        r'\bsecure\s+coding\b',
        r'\bsecurity\s+hole\b',
        r'\bsecurity\s+flaw\b',
        r'\bexploit\b',
        r'\bhardening\b',
        r'\bsanitiz(e|ing)\b',
        r'\binject(ion)?\b',
        r'\bauth(entication|z)?\b',
        r'\bbypass\b',
        r'\bprivilege\s+escalation\b',
        r'\bXSS\b',
        r'\bSQLi\b',
    ]
    
    # First try to find CVE IDs
    cve_matches = cve_pattern.findall(text)
    
    # Check for security keywords
    security_matches = []
    for pattern in security_patterns:
        if re.search(pattern, text, re.IGNORECASE):
            match = re.search(pattern, text, re.IGNORECASE).group(0)
            security_matches.append(match)
    
    result = {
        'cve_ids': cve_matches,
        'security_keywords': list(set(security_matches))  # Remove duplicates
    }
    
    return result

def sanitize_filename(name):
    """Convert a string to a valid filename."""
    # Remove invalid filename characters
    sanitized = re.sub(r'[^\w\-\.]', '_', name)
    # Limit length to avoid filesystem issues
    if len(sanitized) > 100:
        sanitized = sanitized[:100]
    return sanitized

def get_detailed_commit_info(commit_hash):
    """Get comprehensive information about a commit."""
    info = {}
    
    # Basic commit info
    info['hash'] = commit_hash
    info['hash_short'] = commit_hash[:8]
    info['subject'] = run_command(f"git log -1 --pretty=format:%s {commit_hash}")
    info['body'] = run_command(f"git log -1 --pretty=format:%b {commit_hash}")
    info['full_message'] = run_command(f"git log -1 --pretty=format:%B {commit_hash}")
    
    # Author information
    info['author_name'] = run_command(f"git log -1 --pretty=format:%an {commit_hash}")
    info['author_email'] = run_command(f"git log -1 --pretty=format:%ae {commit_hash}")
    info['author_date'] = run_command(f"git log -1 --pretty=format:%ad {commit_hash}")
    info['author_date_iso'] = run_command(f"git log -1 --pretty=format:%aI {commit_hash}")
    
    # Committer information
    info['committer_name'] = run_command(f"git log -1 --pretty=format:%cn {commit_hash}")
    info['committer_email'] = run_command(f"git log -1 --pretty=format:%ce {commit_hash}")
    info['committer_date'] = run_command(f"git log -1 --pretty=format:%cd {commit_hash}")
    info['committer_date_iso'] = run_command(f"git log -1 --pretty=format:%cI {commit_hash}")
    
    # Changed files
    info['files_changed'] = run_command(f"git show --name-only --pretty=format: {commit_hash}").split('\n')
    info['files_changed'] = [f for f in info['files_changed'] if f.strip()]  # Remove empty entries
    info['files_changed_count'] = len(info['files_changed'])
    
    # Stats
    stats_raw = run_command(f"git show --numstat --pretty=format: {commit_hash}")
    stats = []
    for line in stats_raw.split('\n'):
        if line.strip():
            parts = line.split()
            if len(parts) >= 3:
                try:
                    insertions = int(parts[0]) if parts[0] != '-' else 0
                    deletions = int(parts[1]) if parts[1] != '-' else 0
                    file_path = ' '.join(parts[2:])
                    stats.append({
                        'file': file_path,
                        'insertions': insertions,
                        'deletions': deletions
                    })
                except ValueError:
                    continue
    info['stats'] = stats
    
    # Summary numbers
    total_insertions = sum(item['insertions'] for item in stats)
    total_deletions = sum(item['deletions'] for item in stats)
    info['total_insertions'] = total_insertions
    info['total_deletions'] = total_deletions
    info['total_changes'] = total_insertions + total_deletions
    
    # Parent commits
    info['parents'] = run_command(f"git log -1 --pretty=format:%P {commit_hash}").split()
    
    # Branch information (limit to 10 branches to avoid excessive processing)
    branches_raw = run_command(f"git branch --contains {commit_hash} --all | head -10")
    info['branches'] = [b.strip() for b in branches_raw.split('\n') if b.strip()]
    
    # Tags information (limit to 10 tags to avoid excessive processing)
    tags_raw = run_command(f"git tag --contains {commit_hash} | head -10")
    info['tags'] = [t.strip() for t in tags_raw.split('\n') if t.strip()]
    
    # Detect if this is a merge commit
    info['is_merge'] = len(info['parents']) > 1
    
    return info

def process_file(commit_hash, file_path, versions_dir):
    """Process a single file for a commit and save its versions."""
    if not file_path.strip():
        return
    
    safe_file_name = sanitize_filename(file_path)
    
    # Get the pre-commit version (if file existed before)
    pre_version_path = os.path.join(versions_dir, f"{safe_file_name}.pre")
    pre_version = run_command(f"git show {commit_hash}^ -- '{file_path}' 2>/dev/null")
    
    if pre_version:
        with open(pre_version_path, "w") as f:
            f.write(pre_version)
    
    # Get the post-commit version
    post_version_path = os.path.join(versions_dir, f"{safe_file_name}.post")
    post_version = run_command(f"git show {commit_hash}: -- '{file_path}' 2>/dev/null")
    
    if post_version:
        with open(post_version_path, "w") as f:
            f.write(post_version)
    
    # Get the patch for just this file
    files_dir = os.path.dirname(versions_dir).replace("file_versions", "files")
    os.makedirs(files_dir, exist_ok=True)
    
    file_content_path = os.path.join(files_dir, f"{safe_file_name}.patch")
    file_patch = run_command(f"git show {commit_hash} -- '{file_path}'")
    
    with open(file_content_path, "w") as f:
        f.write(file_patch)
    
    return {
        'file': file_path,
        'pre_version': bool(pre_version),
        'post_version': bool(post_version),
        'patch': bool(file_patch)
    }

def process_commit(base_dir, commit_data):
    """Process a single commit with all its details and save to disk."""
    commit_hash, commit_subject = commit_data
    progress_lock = threading.Lock()
    
    try:
        # Extract security identifiers from commit message
        full_message = run_command(f"git log -1 --pretty=format:%B {commit_hash}")
        security_info = extract_security_ids(commit_subject + "\n" + full_message)
        
        if not security_info['cve_ids'] and not security_info['security_keywords']:
            with progress_lock:
                print(f"  Skipping commit {commit_hash[:8]} - no clear security identifiers")
            return None
        
        # Get detailed commit information
        commit_info = get_detailed_commit_info(commit_hash)
        
        # Create a unique folder for each security fix
        if security_info['cve_ids']:
            # For CVE fixes, use the CVE ID in the folder name
            primary_cve = security_info['cve_ids'][0]
            folder_name = f"{primary_cve}_{commit_hash[:7]}"
            fix_type = "cve"
        else:
            # For non-CVE security fixes, use a hash of the commit message for uniqueness
            message_hash = hashlib.md5(commit_subject.encode()).hexdigest()[:12]
            folder_name = f"security_fix_{commit_hash[:7]}_{message_hash}"
            fix_type = "security"
        
        folder_path = os.path.join(base_dir, folder_name)
        
        with progress_lock:
            print(f"Processing: {commit_hash[:8]} - {commit_subject}")
            if os.path.exists(folder_path):
                # Use a unique name if folder already exists
                folder_name = f"{folder_name}_{int(datetime.now().timestamp())}"
                folder_path = os.path.join(base_dir, folder_name)
            
            os.makedirs(folder_path, exist_ok=True)
        
        # Save detailed commit information as JSON
        commit_info['security_info'] = security_info
        commit_info['fix_type'] = fix_type
        
        with open(os.path.join(folder_path, "commit_details.json"), "w") as f:
            json.dump(commit_info, f, indent=2)
        
        # Save human-readable commit information
        with open(os.path.join(folder_path, "commit_info.txt"), "w") as f:
            f.write(f"Commit Hash: {commit_hash}\n")
            f.write(f"Subject: {commit_subject}\n\n")
            
            if security_info['cve_ids']:
                f.write("CVE Identifiers:\n")
                for cve_id in security_info['cve_ids']:
                    f.write(f"- {cve_id}\n")
            
            if security_info['security_keywords']:
                f.write("\nSecurity Keywords:\n")
                for keyword in security_info['security_keywords']:
                    f.write(f"- {keyword}\n")
            
            f.write("\nFull commit message:\n")
            f.write(full_message)
            
            f.write("\n\nMetadata:\n")
            f.write(f"Author: {commit_info['author_name']} <{commit_info['author_email']}>\n")
            f.write(f"Author Date: {commit_info['author_date']}\n")
            f.write(f"Committer: {commit_info['committer_name']} <{commit_info['committer_email']}>\n")
            f.write(f"Commit Date: {commit_info['committer_date']}\n")
            
            f.write(f"\nFiles Changed: {commit_info['files_changed_count']}\n")
            f.write(f"Lines Added: {commit_info['total_insertions']}\n")
            f.write(f"Lines Removed: {commit_info['total_deletions']}\n")
            f.write(f"Total Changes: {commit_info['total_changes']}\n")
        
        # Save the patch file
        patch_file_path = os.path.join(folder_path, "changes.patch")
        with open(patch_file_path, "w") as f:
            patch_content = run_command(f"git show --pretty=format: --patch {commit_hash}")
            f.write(patch_content)
        
        # Save the affected files list
        with open(os.path.join(folder_path, "affected_files.txt"), "w") as f:
            for file_path in commit_info['files_changed']:
                f.write(f"{file_path}\n")
        
        # Create a summary of the changes (stats)
        with open(os.path.join(folder_path, "change_summary.txt"), "w") as f:
            f.write(f"Files changed: {commit_info['files_changed_count']}\n")
            f.write(f"Insertions: {commit_info['total_insertions']}\n")
            f.write(f"Deletions: {commit_info['total_deletions']}\n")
            f.write(f"Total changes: {commit_info['total_changes']}\n\n")
            
            f.write("File-specific changes:\n")
            for stat in commit_info['stats']:
                f.write(f"{stat['file']}: +{stat['insertions']} -{stat['deletions']}\n")
        
        # Create directories for file versions
        versions_dir = os.path.join(folder_path, "file_versions")
        os.makedirs(versions_dir, exist_ok=True)
        
        files_dir = os.path.join(folder_path, "files")
        os.makedirs(files_dir, exist_ok=True)
        
        # Process files in parallel (within this commit)
        # Limit number of threads per commit to avoid overwhelming git
        max_threads_per_commit = min(8, len(commit_info['files_changed']))
        file_process_func = partial(process_file, commit_hash, versions_dir=versions_dir)
        
        file_results = []
        
        # For commits with few files, process sequentially to avoid overhead
        if len(commit_info['files_changed']) <= 5:
            for file_path in commit_info['files_changed']:
                result = file_process_func(file_path)
                if result:
                    file_results.append(result)
        else:
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads_per_commit) as executor:
                futures = [executor.submit(file_process_func, file_path) 
                           for file_path in commit_info['files_changed']]
                
                for future in concurrent.futures.as_completed(futures):
                    result = future.result()
                    if result:
                        file_results.append(result)
        
        # Update the commit info with file processing results
        commit_info['file_results'] = file_results
        
        # Final update to the JSON file with file processing results
        with open(os.path.join(folder_path, "commit_details.json"), "w") as f:
            json.dump(commit_info, f, indent=2)
        
        with progress_lock:
            print(f"  ✓ Completed: {commit_hash[:8]} ({len(file_results)} files processed)")
        
        return {
            'commit_hash': commit_hash,
            'commit_hash_short': commit_hash[:8],
            'subject': commit_subject,
            'folder': folder_name,
            'fix_type': fix_type,
            'cve_ids': security_info['cve_ids'],
            'security_keywords': security_info['security_keywords'],
            'date': commit_info['author_date_iso'],
            'author': f"{commit_info['author_name']} <{commit_info['author_email']}>",
            'files_changed': commit_info['files_changed_count'],
            'total_changes': commit_info['total_changes']
        }
    
    except Exception as e:
        with progress_lock:
            print(f"Error processing commit {commit_hash[:8]}: {str(e)}")
        return None

def main():
    start_time = datetime.now()
    
    # Create a base directory for all security fixes
    base_dir = f"buggy_database{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    os.makedirs(base_dir, exist_ok=True)
    
    print(f"Created base directory: {base_dir}")
    
    # Get all commits that might contain security fixes
    print("Searching for security-related commits...")
    
    # Use multiple search patterns to catch different commit message formats
    search_patterns = [
        "CVE-", 
        "security fix", 
        "security issue", 
        "security vulnerability", 
        "security bug",
        "vulnerability",
        "sec-",
        "security patch",
        "exploit",
        "buffer overflow",
        "memory leak",
        "race condition",
        "authentication",
        "authorization",
        "injection",
        "XSS",
        "SQLi",
        "CSRF",
        "privilege escalation",
        "hardening"
    ]
    
    # Create a comprehensive security fixes index
    index = {
        'repository': run_command("git config --get remote.origin.url"),
        'scan_date': datetime.now().isoformat(),
        'fixes': []
    }
    
    # Get all commits
    commits = []
    seen_hashes = set()
    
    for pattern in search_patterns:
        git_log_command = f"git log --grep='{pattern}' -i --pretty=format:'%H|%s'"
        commits_raw = run_command(git_log_command)
        
        if commits_raw:
            for line in commits_raw.split('\n'):
                if line:  # Skip empty lines
                    parts = line.split('|', 1)
                    if len(parts) == 2:
                        commit_hash, commit_subject = parts
                        # Avoid duplicates
                        if commit_hash not in seen_hashes:
                            commits.append((commit_hash, commit_subject))
                            seen_hashes.add(commit_hash)
    
    if not commits:
        print("No security-related commits found.")
        return
    
    print(f"Found {len(commits)} potential security-related commits.")
    print(f"Using {get_cpu_count()} CPU cores for parallel processing.")
    
    # Process commits in parallel
    processed_commits = []
    
    # Using ProcessPoolExecutor to fully utilize CPU cores
    with concurrent.futures.ProcessPoolExecutor(max_workers=get_cpu_count()) as executor:
        process_func = partial(process_commit, base_dir)
        
        # Submit all commits for processing
        futures = {executor.submit(process_func, commit): commit for commit in commits}
        
        # Collect results as they complete
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                processed_commits.append(result)
                
    # Sort processed commits by date
    processed_commits.sort(key=lambda x: x.get('date', ''))
    
    # Update the index
    index['fixes'] = processed_commits
    index['total_commits_processed'] = len(processed_commits)
    index['total_commits_found'] = len(commits)
    index['processing_time_seconds'] = (datetime.now() - start_time).total_seconds()
    
    # Save the index
    with open(os.path.join(base_dir, "security_fixes_index.json"), "w") as f:
        json.dump(index, f, indent=2)
    
    # Count CVE fixes
    cve_fixes = [fix for fix in processed_commits if fix['fix_type'] == 'cve']
    
    # Create a human-readable summary
    with open(os.path.join(base_dir, "summary.txt"), "w") as f:
        f.write(f"Security Fixes Summary\n")
        f.write(f"=====================\n\n")
        f.write(f"Repository: {index['repository']}\n")
        f.write(f"Scan Date: {index['scan_date']}\n")
        f.write(f"Total Security Fixes Found: {len(processed_commits)}\n")
        f.write(f"Processing Time: {index['processing_time_seconds']:.2f} seconds\n\n")
        
        f.write(f"CVE Fixes: {len(cve_fixes)}\n")
        f.write(f"Other Security Fixes: {len(processed_commits) - len(cve_fixes)}\n\n")
        
        f.write(f"List of Security Fixes:\n")
        f.write(f"=====================\n\n")
        
        # Sort by date for the summary
        for i, fix in enumerate(processed_commits, 1):
            f.write(f"{i}. [{fix['commit_hash_short']}] {fix['subject']}\n")
            if fix['cve_ids']:
                f.write(f"   CVE IDs: {', '.join(fix['cve_ids'])}\n")
            f.write(f"   Date: {fix['date']}\n")
            f.write(f"   Author: {fix['author']}\n")
            f.write(f"   Files Changed: {fix['files_changed']}\n")
            f.write(f"   Folder: {fix['folder']}\n")
            f.write("\n")
    
    end_time = datetime.now()
    elapsed = (end_time - start_time).total_seconds()
    
    print("\nSummary:")
    print(f"Processed {len(processed_commits)} security-related commits out of {len(commits)} potential matches")
    print(f"CVE Fixes: {len(cve_fixes)}")
    print(f"Other Security Fixes: {len(processed_commits) - len(cve_fixes)}")
    print(f"Total processing time: {elapsed:.2f} seconds")
    print(f"Results saved in {os.path.abspath(base_dir)}")
    print(f"Index file: {os.path.join(base_dir, 'security_fixes_index.json')}")
    print(f"Summary file: {os.path.join(base_dir, 'summary.txt')}")

if __name__ == "__main__":
    # Make sure we're in a git repository
    if not os.path.exists(".git"):
        print("Error: This script must be run from within a Git repository.")
        exit(1)
    
    main()
