from typing import Optional
from megavul.util.utils import get_bs4_parsed_html, get_final_redirect_url
from megavul.git_platform.github_pf import find_commit_from_commit_msg_in_github
from megavul.util.storage import StorageLocation
from megavul.git_platform.gitweb_pf import  find_gitweb_commits_in_search_page
import re

COMMIT_THRESHOLD = 5

def commit_threshold_return(commits:list[str]) -> list[str]:
    if len(commits) > COMMIT_THRESHOLD:
        return []
    return commits

def find_sourceware_commit_from_comment(sourceware_url: str) -> list[str]:
    assert 'sourceware.org/bugzilla/show_bug.cgi' in sourceware_url

    commits_result = []
    page = get_bs4_parsed_html(sourceware_url)

    bz_field_status = page.find('td', id='bz_field_status')
    if bz_field_status is None:
        return []

    status = ' '.join([s.strip() for s in bz_field_status.text.strip().split('\n')])
    if status != 'RESOLVED FIXED':  # this issue has not been resolved
        return []

    comments = page.find_all('div', class_='bz_comment')

    for comment in comments:
        comment_user: str = comment.find("span", class_="bz_comment_user").text
        comment_user = comment_user.strip()
        if comment_user != 'cvs-commit@gcc.gnu.org':  # sourceware BOT
            continue
        content = comment.find('pre', class_='bz_comment_text')
        commit_urls = content.find_all('a', attrs={'rel': 'ugc'})
        commit_urls = [url.text for url in commit_urls]
        commit_urls = list(filter(lambda x: 'h=' in x, commit_urls))  # commit url
        if len(commit_urls) > 5:  # big change, drop it
            break
        commits_result.extend(commit_urls)
        break  # only care about the BOT first comment
    return commits_result


def find_xen_commit_from_advisory(advisory_url: str) -> [str]:
    advisory_page = get_bs4_parsed_html(advisory_url)
    table = advisory_page.find('table')
    if table is None:
        return []
    xsa_id: str = table.tr.td.a.text.lower()

    # only find the commit contains the following msg
    # This is XSA-83.
    # This is CVE-2014-2986 / XSA-94.
    # This is XSA-91 / CVE-2014-3125.
    # This is part of CVE-2014-5147 / XSA-102.
    # This is part of XSA-222.

    match_re = rf'this is (cve[^\s]* / )?{xsa_id}|this is part of (cve[^\s]* / )?{xsa_id}'
    return find_commit_from_commit_msg_in_github('xen-project/xen', xsa_id, regex_match=match_re)


def find_commit_from_chromium_code_review(review_url: str) ->  Optional[str]:
    assert 'codereview.chromium.org' in review_url
    review_page = get_bs4_parsed_html(review_url)
    issue_desc = review_page.find('div', id='issue-description')
    if issue_desc is None:
        return None
    issue_desc = issue_desc.text
    issue_desc = list(filter(lambda x: 'Committed: http' in x, issue_desc.split('\n')))
    if len(issue_desc) > 0:
        url = issue_desc[0]
        url = url[url.index('http'):]
        # filter http://src.chromium.org/viewvc/chrome?view=rev&revision=86862 url
        if 'viewvc' in url:
            return None
        # convert https://crrev.com/6703b5a51cedaa0ead73047d969f8c04362f51f1 to https://chromium.googlesource.com/xxx
        url = get_final_redirect_url(url)
        # only select contains `googlesource` keyword url
        if 'googlesource' not in url:
            return None
        return url
    return None


chromium_log_msg2hash = None


def find_chromium_commit_from_viewvc(viewvc_url: str) -> Optional[str]:
    global chromium_log_msg2hash
    if chromium_log_msg2hash is None:
        chromium_log = (StorageLocation.storage_dir() / 'chromium_log.txt').open(mode='r')
        chromium_log_lines = chromium_log.readlines()
        chromium_log_msg2hash = {}
        for l in chromium_log_lines:
            hash, msg = l.split('||||||||||')
            msg = msg.strip()
            if msg in chromium_log_msg2hash.keys():
                chromium_log_msg2hash[msg] = None
            chromium_log_msg2hash[msg] = hash

    viewvc_page = get_bs4_parsed_html(viewvc_url)
    vc_log = viewvc_page.find('pre', class_='vc_log')
    if vc_log is None:
        return None
    vc_log = vc_log.text.split('\n')[0]
    if vc_log in chromium_log_msg2hash.keys():
        hash = chromium_log_msg2hash[vc_log]
        if hash is None:
            return None
        url = f'https://github.com/chromium/chromium/commit/{hash}'
        return url
    else:
        return None


def find_url_from_debian_security_tracker(security_tracker_url: str) -> [str]:
    page = get_bs4_parsed_html(security_tracker_url)
    node_contents = page.find('pre')
    if node_contents is None:
        return []
    node_contents = node_contents.get_text(separator='\n', strip=True)
    url_pattern = r'https?://[^\s]+'
    url_result = []
    for line in node_contents.split('\n'):
        if line.startswith('Introduced by:'):
            continue
        urls = re.findall(url_pattern, line)
        url_result.extend(urls)
    return commit_threshold_return(url_result)


def find_commit_from_moodle_discuss(discuss_url: str) -> [str]:
    discuss_page = get_bs4_parsed_html(discuss_url)
    post_content = discuss_page.find('div',class_='post-content-container')
    if post_content is None: return []
    post_content = post_content.get_text(separator='\n', strip=True)
    url_pattern = r'https?://[^\s]+'
    url_result = []
    for line in post_content.split('\n'):
        urls = re.findall(url_pattern, line)
        for url in urls:
            if 'a=search' in url:
                url_result.extend(find_gitweb_commits_in_search_page(url))
            elif 'a=commit' in url:
                url = url.replace('%3B', ';').replace('a=commitdiff', 'a=commit')
                url_result.append(url)

    return commit_threshold_return(url_result)

def find_commit_from_php_issue(php_issue_url:str) -> [str]:
    assert 'bug.php?id=' in php_issue_url
    php_issue_page = get_bs4_parsed_html(php_issue_url)
    commit_hash_set = set()
    for note in php_issue_page.find_all('div',class_='comment type_svn'):
        note_href = note.find('a',attrs={'rel':'nofollow'})
        commit_url = note_href.text
        if 'viewvc' in commit_url:
            # skip viewvc URL e.g. http://svn.php.net/viewvc/?view=revision&amp;revision=318938
            continue
        commit_hash = commit_url[commit_url.find('h=') + 2 :]
        commit_hash_set.add(commit_hash)

    # transform to GitHub commit
    commit_urls = list(map(lambda x:f"https://github.com/php/php-src/commit/{x}", commit_hash_set))
    return commit_urls

def find_commit_from_rustsec(sec_url : str) -> [str]:
    page = get_bs4_parsed_html(sec_url)
    page.find('dl')
    dts = page.find_all('dt')
    dds = page.find_all('dd')
    url_result = []
    for dt,dd in zip(dts,dds):
        if  'id' in dt.attrs.keys() and  dt['id'] == 'details':
            for one_url in dd.find_all('a'):
                url_result.append(one_url.text.strip())

    return url_result

def find_commit_from_gnome_bugzilla(gnome_url: str) -> [str]:
    assert 'bugzilla.gnome.org/show_bug.cgi' in gnome_url

    commits_result = []
    page = get_bs4_parsed_html(gnome_url)
    if page.find('td', id='bz_field_status') is None:
        return []

    status = ' '.join([s.strip() for s in page.find('td', id='bz_field_status').text.strip().split('\n')])
    if status != 'RESOLVED FIXED':  # this issue has not been resolved
        return []

    comments = page.find_all('pre',class_='bz_comment_text')
    for c in comments:
        commit_pattern = c.text.find('Author:') != -1 and c.text.find('Date:') != -1
        # commit pattern
        # ###################################################################
        # commit 66003c7fee310f203c9947864429e03e652e02e7
        # Author: xxx <xxxx@gimp.org>
        # Date:   Sat Apr 14 14:26:37 2018 +0200
        if not commit_pattern:
            continue
        all_a = c.find_all('a')
        for a in all_a:
            url = a['href']
            if 'commit' in url:
                commits_result.append(url)
                break

    commits_result = list(map(lambda x: (x.replace('http://', 'https://')
                              .replace('gitlab.gnome.org', 'github.com')
                              .replace('git.gnome.org', 'github.com')
                              .replace('browse', 'GNOME')
                              .replace('/-/', '/')
                              .replace('?id=','')
                                         ), set(commits_result)))

    return commits_result

def find_commit_from_ghostscript_bugzilla(ghost_url: str) -> [str]:
    assert 'bugs.ghostscript.com/show_bug.cgi' in ghost_url

    commits_result = []
    page = get_bs4_parsed_html(ghost_url)
    if page.find('td', id='bz_field_status') is None:
        return []

    status = ' '.join([s.strip() for s in page.find('td', id='bz_field_status').text.strip().split('\n')])
    if status != 'RESOLVED FIXED':  # this issue has not been resolved
        return []

    comments = page.find_all('pre',class_='bz_comment_text')
    for c in comments:
        comment_text = c.text.lower()
        commit_pattern = comment_text.find('author:') != -1 and comment_text.find('date:') != -1
        fix_in_pattern = comment_text.find('fixed in') != -1 or comment_text.find('fix in') != -1
        # fix in pattern
        # ###################################################################
        # Fixed in commit 0a7e5a1c309fa0911b892fa40996a7d55d90bace
        if not commit_pattern or not fix_in_pattern:
            continue
        all_a = c.find_all('a')
        for a in all_a:
            url = a['href']
            if 'commit' in url or 'findgit.cgi' in url:
                commits_result.append(get_final_redirect_url(url))
                break

    commits_result = list(set(commits_result))

    return commits_result

if __name__ == '__main__':
    ...
    # https://bugzilla.gnome.org/show_bug.cgi?id=778519

    # find_commit_from_gnome_bugzilla('https://bugzilla.gnome.org/show_bug.cgi?id=790853')
    # find_commit_from_gnome_bugzilla('https://bugzilla.gnome.org/show_bug.cgi?id=600741')
    # print(find_commit_from_gnome_bugzilla('https://bugzilla.gnome.org/show_bug.cgi?id=794914'))
    # print(find_commit_from_ghostscript_bugzilla('http://bugs.ghostscript.com/show_bug.cgi?id=696941'))

    # find_commit_from_rustsec('https://rustsec.org/advisories/RUSTSEC-2018-0019.html')
    # find_commit_from_php_issue('https://bugs.php.net/bug.php?id=73029')
    # find_commit_from_moodle_discuss('https://moodle.org/mod/forum/discuss.php?d=188309')