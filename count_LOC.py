import os
from pathlib import Path
from collections import defaultdict

def count_lines(file_path):
    """Count total lines, code lines, blank lines, and comment lines in a file."""
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
    except Exception as e:
        print(f"Error reading {file_path}: {e}")
        return None
    
    total_lines = len(lines)
    blank_lines = 0
    comment_lines = 0
    code_lines = 0
    
    in_multiline_comment = False
    in_html_comment = False
    file_ext = Path(file_path).suffix.lower()
    
    for line in lines:
        stripped = line.strip()
        
        # Blank line check
        if not stripped:
            blank_lines += 1
            continue
        
        if file_ext == '.py':
            # Python multiline string/comment handling
            if in_multiline_comment:
                comment_lines += 1
                if '"""' in stripped or "'''" in stripped:
                    in_multiline_comment = False
                continue
            
            # Check for multiline comment start
            if stripped.startswith('"""') or stripped.startswith("'''"):
                comment_lines += 1
                # Check if it ends on the same line
                quote = '"""' if stripped.startswith('"""') else "'''"
                if stripped.count(quote) == 1:
                    in_multiline_comment = True
                continue
            
            # Single line comment
            if stripped.startswith('#'):
                comment_lines += 1
                continue
            
            code_lines += 1
            
        elif file_ext == '.html':
            # HTML comment handling
            if in_html_comment:
                comment_lines += 1
                if '-->' in stripped:
                    in_html_comment = False
                continue
            
            if stripped.startswith('<!--'):
                comment_lines += 1
                if '-->' not in stripped:
                    in_html_comment = True
                continue
            
            code_lines += 1
        else:
            code_lines += 1
    
    return {
        'total': total_lines,
        'code': code_lines,
        'blank': blank_lines,
        'comment': comment_lines
    }

def find_files(root_dir, extensions):
    """Find all files with given extensions in directory tree."""
    files = []
    exclude_dirs = {'__pycache__', '.git', 'node_modules', 'venv', '.venv', 'env', '.env'}
    
    for dirpath, dirnames, filenames in os.walk(root_dir):
        # Remove excluded directories from search
        dirnames[:] = [d for d in dirnames if d not in exclude_dirs]
        
        for filename in filenames:
            if any(filename.endswith(ext) for ext in extensions):
                files.append(os.path.join(dirpath, filename))
    
    return files

def count_loc(root_dir='.'):
    """Main function to count LOC for .py and .html files."""
    root_path = Path(root_dir).resolve()
    print(f"\n{'='*70}")
    print(f"LOC Counter - Scanning: {root_path}")
    print(f"{'='*70}\n")
    
    # Find all relevant files
    py_files = find_files(root_dir, ['.py'])
    html_files = find_files(root_dir, ['.html'])
    
    results = {
        '.py': {'files': [], 'totals': defaultdict(int)},
        '.html': {'files': [], 'totals': defaultdict(int)}
    }
    
    # Process Python files
    print("📁 PYTHON FILES (.py)")
    print("-" * 70)
    print(f"{'File':<50} {'Total':>8} {'Code':>8} {'Blank':>8}")
    print("-" * 70)
    
    for file_path in sorted(py_files):
        counts = count_lines(file_path)
        if counts:
            rel_path = os.path.relpath(file_path, root_dir)
            results['.py']['files'].append((rel_path, counts))
            for key, value in counts.items():
                results['.py']['totals'][key] += value
            
            # Truncate long paths for display
            display_path = rel_path if len(rel_path) <= 48 else '...' + rel_path[-45:]
            print(f"{display_path:<50} {counts['total']:>8} {counts['code']:>8} {counts['blank']:>8}")
    
    print("-" * 70)
    py_totals = results['.py']['totals']
    print(f"{'PYTHON TOTAL':<50} {py_totals['total']:>8} {py_totals['code']:>8} {py_totals['blank']:>8}")
    print(f"Files: {len(py_files)}\n")
    
    # Process HTML files
    print("\n📁 HTML FILES (.html)")
    print("-" * 70)
    print(f"{'File':<50} {'Total':>8} {'Code':>8} {'Blank':>8}")
    print("-" * 70)
    
    for file_path in sorted(html_files):
        counts = count_lines(file_path)
        if counts:
            rel_path = os.path.relpath(file_path, root_dir)
            results['.html']['files'].append((rel_path, counts))
            for key, value in counts.items():
                results['.html']['totals'][key] += value
            
            display_path = rel_path if len(rel_path) <= 48 else '...' + rel_path[-45:]
            print(f"{display_path:<50} {counts['total']:>8} {counts['code']:>8} {counts['blank']:>8}")
    
    print("-" * 70)
    html_totals = results['.html']['totals']
    print(f"{'HTML TOTAL':<50} {html_totals['total']:>8} {html_totals['code']:>8} {html_totals['blank']:>8}")
    print(f"Files: {len(html_files)}\n")
    
    # Grand Summary
    print("\n" + "=" * 70)
    print("📊 GRAND SUMMARY")
    print("=" * 70)
    print(f"{'Category':<20} {'Files':>10} {'Total Lines':>15} {'Code Lines':>15}")
    print("-" * 70)
    print(f"{'Python (.py)':<20} {len(py_files):>10} {py_totals['total']:>15} {py_totals['code']:>15}")
    print(f"{'HTML (.html)':<20} {len(html_files):>10} {html_totals['total']:>15} {html_totals['code']:>15}")
    print("-" * 70)
    
    grand_total_files = len(py_files) + len(html_files)
    grand_total_lines = py_totals['total'] + html_totals['total']
    grand_code_lines = py_totals['code'] + html_totals['code']
    
    print(f"{'GRAND TOTAL':<20} {grand_total_files:>10} {grand_total_lines:>15} {grand_code_lines:>15}")
    print("=" * 70)
    
    return results

if __name__ == '__main__':
    import sys
    
    # Use command line argument or current directory
    directory = sys.argv[1] if len(sys.argv) > 1 else '.'
    count_loc(directory)