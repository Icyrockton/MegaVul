import logging
from urllib.parse import urlparse
import re
from multiprocessing.process import current_process
from typing import Optional
from vul4c.pipeline.json_save_location import cve_with_reference_url_json_path, all_cve_from_nvd_json_path
from vul4c.util.storage import StorageLocation
from vul4c.util.utils import read_json_from_local, save_str, filter_duplicate, get_final_redirect_url, \
    save_marshmallow_dataclass_to_json_file
from vul4c.util.logging_util import global_logger
from vul4c.util.concurrent_util import multiprocessing_apply_data_with_logger
from ordered_set import OrderedSet
from vul4c.pipeline.extract_cve_info_util import find_sourceware_commit_from_comment, find_xen_commit_from_advisory, \
    find_commit_from_chromium_code_review, find_chromium_commit_from_viewvc, find_url_from_debian_security_tracker, \
    find_commit_from_moodle_discuss, find_commit_from_php_issue, find_commit_from_rustsec, \
    find_commit_from_gnome_bugzilla, find_commit_from_ghostscript_bugzilla
from vul4c.git_platform.gitweb_pf import find_gitweb_commits_in_search_page
from vul4c.git_platform.gitlab_pf import find_commits_from_gitlab
from vul4c.git_platform.github_pf import find_potential_commits_from_github
from vul4c.git_platform.common import CvssMetrics, CveWithReferenceUrl


def extract_description(descriptions: list) -> str:
    for d in descriptions:
        if d['lang'] == 'en':
            return d['value']
    return ''


def extract_cvss_metrics(logger: logging.Logger, metrics: dict) -> CvssMetrics:
    #  e.g. CVE-2022-3547, CVE-2022-30222
    cvss_vector: Optional[str] = None
    is_cvss_v3: Optional[bool] = None
    base_score: Optional[float] = None
    base_severity: Optional[str] = None

    def find_primary_index(data: list):
        final_idx = 0
        for idx, x in enumerate(data):
            if x['type'] == 'Primary':
                final_idx = idx
        return final_idx

    if 'cvssMetricV2' in metrics:
        p_idx = find_primary_index(metrics['cvssMetricV2'])
        metrics = metrics['cvssMetricV2'][p_idx]
        cvss_data = metrics['cvssData']
        cvss_vector = cvss_data['vectorString']
        base_score = cvss_data['baseScore']
        base_severity = metrics['baseSeverity']
        is_cvss_v3 = False
    elif 'cvssMetricV31' in metrics:
        p_idx = find_primary_index(metrics['cvssMetricV31'])
        metrics = metrics['cvssMetricV31'][p_idx]
        is_cvss_v3 = True
        cvss_data = metrics['cvssData']
        cvss_vector = cvss_data['vectorString']
        base_score = cvss_data['baseScore']
        base_severity = cvss_data['baseSeverity']
    else:
        logger.warning(f'unknown cvss version {metrics.keys()}')
    return CvssMetrics(cvss_vector, base_score, base_severity, is_cvss_v3)


def extract_cwe_ids(weaknesses: list[dict]) -> list[str]:
    cwe_other = ['NVD-CWE-noinfo', 'NVD-CWE-Other']
    found_cwe_other = False
    cwe_id = set()
    for w in weaknesses:
        if w['type'] == 'Primary':
            for d in w['description']:
                if d['lang'] == 'en':
                    if d['value'] not in cwe_other:
                        cwe_id.add(d['value'])
                    else:
                        found_cwe_other = True
    if len(cwe_id) == 0:  # from Secondary or other
        for w in weaknesses:
            for d in w['description']:
                if d['lang'] == 'en':
                    if d['value'] not in cwe_other:
                        cwe_id.add(d['value'])
                    else:
                        found_cwe_other = True
    if len(cwe_id) == 0 and found_cwe_other:
        cwe_id.add('CWE-Other')  # ['NVD-CWE-noinfo', 'NVD-CWE-Other']
    return list(cwe_id)


def mining_commit_urls_from_reference_urls(logger: logging.Logger, urls: list[str]):
    """ mining commit url and fix some corrupted url  """
    url_result = []
    for url in urls:
        parse_url = urlparse(url)
        nloc = parse_url.netloc

        if nloc == 'github.com':
            commit_urls = find_potential_commits_from_github(logger, url, urls)
            url_result.extend(commit_urls)
        elif nloc == 'git.kernel.org':
            # https://nvd.nist.gov/vuln/detail/CVE-2014-0155
            if 'commit' not in url:
                # get final URL from short URL
                # e.g. http://git.kernel.org/linus/c19483cc5e56ac5e22dd19cf25ba210ab1537773
                #      https://git.kernel.org/linus/07721feee46b4b248402133228235318199b05ec
                url = get_final_redirect_url(url)
            url = url.replace('%3B', ';').replace('a=commitdiff_plain',
                                                  'a=commitdiff').replace('id=',
                                                                          'h=')  # some commit url has `%3B` ,  replace it with `;`
            # remove linux version number (e.g. linux-2.6 linux-2.3.65 to linux ,  testing-2.6.git to testing.git )
            if (version_re := re.search(r'(\w*?-[0-9]\.[\w.]*?\.git)', url)) is not None:
                replace_str = version_re.group(0)
                new_name = f"{replace_str.split('-')[0]}.git"
                url = url.replace(replace_str, new_name)
            # filter missing commit hash url
            if not "h=" in url or '/diff/' in url or '/tree/' in url or '/patch/' in url:
                continue
            url_result.append(url)
        elif nloc == 'sourceware.org':
            if 'h=' in url:
                # 1. find commit URL first
                url = url.replace('%3B', ';')
                url_result.append(url)
            elif 'sourceware.org/bugzilla/show_bug.cgi' in url:
                # 2. find commit URL from issue's comments.
                url_result.extend(find_sourceware_commit_from_comment(url))
        elif nloc == 'android.googlesource.com':
            if url.endswith('.txt') or url.endswith('.java') or url.endswith('.cpp'):
                continue
            url = url.replace(',', '')
            url_result.append(url)
        elif nloc == 'xenbits.xen.org' and ('advisory' in url):
            xen_commits = find_xen_commit_from_advisory(url)
            url_result.extend(xen_commits)
        elif nloc == 'code.wireshark.org' and ('h=' in url):
            # wireshark url transform to GitHub url
            # https://code.wireshark.org/review/gitweb?p=wireshark.git;a=commit;h=5b4ada17723ed8af7e85cb48d537437ed614e417
            url = url.replace('%3B', ';')
            commit_hash = url[url.index('h=') + 2:]
            url = f'https://github.com/wireshark/wireshark/commit/{commit_hash}'
            url_result.append(url)
        elif nloc == 'codereview.chromium.org':
            commit_url = find_commit_from_chromium_code_review(url)
            if commit_url is not None:
                url_result.append(commit_url)
        elif nloc == 'git.videolan.org' and ('h=' in url):
            url = url.replace('%3B', ';').replace('a=commitdiff', 'a=commit')
            url_result.append(url)
        elif nloc == 'git.moodle.org':
            url = url.replace('%3B', ';').replace('a=commitdiff', 'a=commit')
            if 'a=commit' in url:
                url_result.append(url)
            elif 'a=search' in url:
                url_result.extend(find_gitweb_commits_in_search_page(url))
        elif nloc == 'cgit.freedesktop.org':
            if 'commit' in url:
                url_result.append(url)
            elif 'diff' in url:
                # replace diff to commit
                url = url.replace('diff', 'commit')
                url_result.append(url)
        elif nloc == 'git.gnome.org':
            # transform GNOME self hosted gitlab url to github url
            url = get_final_redirect_url(url)
            if url != 'https://gitlab.gnome.org/users/sign_in':
                github_url = (url.replace('http://', 'https://')
                              .replace('gitlab.gnome.org', 'github.com')
                              .replace('browse', 'GNOME')
                              .replace('/-/', '/'))
                url_result.append(github_url)
        elif nloc == 'git.openssl.org' and 'commit' in url:
            url = url.replace('%3B', ';').replace('a=commitdiff', 'a=commit')
            url_result.append(url)
        elif nloc == 'git.savannah.gnu.org':
            url = url.replace('%3B', ';').replace('a=commitdiff', 'a=commit').replace('a=commit_plain','a=commit').replace('patch', 'commit')
            if 'commit' in url:
                url_result.append(url)
        elif nloc == 'git.ghostscript.com':
            # ghostscript server is down. transform url to github url
            # http://git.ghostscript.com/?p=mupdf.git;h=96751b25462f83d6e16a9afaf8980b0c3f979c8b
            url = url.replace('%3B', ';').replace('a=commitdiff', 'a=commit')
            url = url.split('?')[1].split(';')
            repo = None
            commit_hash = None
            for u in url:
                if u.startswith('p='):
                    repo = u[2:].split('.')[0]
                elif u.startswith('h='):
                    commit_hash = u[2:]
            if repo is not None and commit_hash is not None:
                url = f'https://github.com/ArtifexSoftware/{repo}/commit/{commit_hash}'
                url_result.append(url)
        elif nloc == 'gitlab.gnome.org':
            # transform GNOME self hosted gitlab url to github url
            if url.endswith('.c') or url.endswith('.patch'):
                continue

            def gitlab_url_to_github_url(url: str) -> str:
                return url.replace('http://', 'https://').replace('gitlab.gnome.org', 'github.com').replace('browse',
                                                                                                            'GNOME').replace(
                    '/-/', '/')

            if 'commit' in url:
                url = gitlab_url_to_github_url(url)
                url_result.append(url)
            else:
                gitlab_urls = find_commits_from_gitlab(url)
                url_result.extend([gitlab_url_to_github_url(url) for url in gitlab_urls])
        elif nloc == 'gitlab.freedesktop.org':
            if 'diffs?commit_id' in url:
                url = url[:url.find('diffs?commit_id') - 1]

            def gitlab_url_to_cgit_url(url: str) -> str:
                path = urlparse(url).path
                path = path.replace('/-/', '/').replace('/commit/', '/')
                commit_hash = path.split('/')[-1]
                repo_mapping = {
                    'xorg/lib/libxpm': 'xorg/lib/libXpm',
                    'virgl/virglrenderer': 'virglrenderer',
                    'xorg/lib/libx11': 'xorg/lib/libX11',
                    'polkit/polkit': 'polkit',
                    'libbsd/libbsd': 'libbsd',
                    'cairo/cairo': 'cairo',
                    'pixman/pixman': 'pixman',
                }
                repo = '/'.join(path[1:].split('/')[:-1])
                if repo in repo_mapping.keys():
                    repo = repo_mapping[repo]
                url = f'https://cgit.freedesktop.org/{repo}/commit/?id={commit_hash}'
                return url

            if 'commit' in url:
                url_result.append(gitlab_url_to_cgit_url(url))
            else:
                gitlab_urls = find_commits_from_gitlab(url)
                url_result.extend([gitlab_url_to_cgit_url(url) for url in gitlab_urls])
        elif nloc == 'src.chromium.org':
            if 'viewvc' in url:
                commit_url = find_chromium_commit_from_viewvc(url)
                if commit_url is not None:
                    url_result.append(commit_url)
        elif nloc == 'git.qemu.org':
            if 'commit' in url:
                url = (url.replace('%3B', ';')
                       .replace('a=commitdiff', 'a=commit')
                       .replace('id=', 'h=')
                       .replace('gitweb.cgi', '')
                       )
                # transform to GitHub url
                commit_hash = url[url.find('h=') + 2:]
                url = f'https://github.com/qemu/qemu/commit/{commit_hash}'
                url_result.append(url)
        elif nloc == 'gitlab.com':
            if '/commit/' in url:
                url = url.split('#')[0].split('?')[0]
                url_result.append(url)
            elif ('/issues/' in url or '/merge_requests/' in url) and (
                    not url.startswith('https://gitlab.com/gitlab-org')):  # Do NOT track gitlab-org repo
                gitlab_urls = find_commits_from_gitlab(url)
                url_result.extend(gitlab_urls)
        elif nloc == 'security-tracker.debian.org':
            # e.g.
            # https://security-tracker.debian.org/tracker/CVE-2013-7087
            # https://nvd.nist.gov/vuln/detail/CVE-2013-7087
            potential_urls = find_url_from_debian_security_tracker(url)
            extracted_urls = mining_commit_urls_from_reference_urls(logger, potential_urls)
            url_result.extend(extracted_urls)
        elif nloc == 'moodle.org':
            if 'discuss.php' in url:
                # https://nvd.nist.gov/vuln/detail/CVE-2017-7491
                # https://moodle.org/mod/forum/discuss.php?d=352355
                #
                # https://nvd.nist.gov/vuln/detail/CVE-2018-1137
                # https://moodle.org/mod/forum/discuss.php?d=371204
                commit_urls = find_commit_from_moodle_discuss(url)
                url_result.extend(commit_urls)
        elif nloc == 'bugs.php.net':
            if 'bug.php' in url:
                commit_urls = find_commit_from_php_issue(url)
                url_result.extend(commit_urls)
        elif nloc == 'rustsec.org':
            raw_urls = find_commit_from_rustsec(url)
            extracted_urls = mining_commit_urls_from_reference_urls(logger, raw_urls)
            url_result.extend(extracted_urls)
        elif nloc == 'bugzilla.gnome.org':
            if 'show_bug.cgi' in url:
                commit_urls = find_commit_from_gnome_bugzilla(url)
                url_result.extend(commit_urls)
        elif nloc == 'bugs.ghostscript.com':
            if 'show_bug.cgi' in url:
                commit_urls = find_commit_from_ghostscript_bugzilla(url)
                if len(commit_urls) != 0:
                    # git.ghostscript.com/xxxxxx
                    extracted_urls = mining_commit_urls_from_reference_urls(logger, commit_urls)
                    url_result.extend(extracted_urls)
        elif nloc == 'go.dev':
            if 'issue' in url:
                commit_urls = mining_commit_urls_from_reference_urls(logger, [get_final_redirect_url(url)])
                if len(commit_urls) <= 3:  # drop big commits
                    url_result.extend(commit_urls)
        elif nloc == 'git.php.net':
            if 'commit' in url:
                url = (url.replace('%3B', ';')
                       .replace('a=commitdiff', 'a=commit')
                       .replace('id=', 'h='))
                commit_hash = url[url.find('h=') + 2:]
                commit_url = f'https://github.com/php/php-src/commit/{commit_hash}'
                url_result.append(commit_url)
        else:
            logger.debug(f'unknown reference URL: {url}')

    return url_result


# dumping website flag, result will save into `./storage/dump_website`
# enabled only when analyzing the source website to be mined
DUMP_URL_FLAG = False
DUMP_URL_FREQUENCY = 50
ALL_CVE_REFERENCE_URL: list[str] = []


def dump_url():
    global_logger.info('dumping all cve entries reference URLs, grouped by website...')
    website_url_dict = {}
    global_logger.info(f'total reference URLs:{len(ALL_CVE_REFERENCE_URL)}')

    for u in ALL_CVE_REFERENCE_URL:
        netloc = urlparse(u).netloc
        website_url_dict.setdefault(netloc, [])
        website_url_dict[netloc].append(u)

    global_logger.info(f'reference URLs from {len(website_url_dict)} different websites')

    url_filter_by_frequency = {k: v for k, v in
                               sorted(filter(lambda item: len(item[1]) > DUMP_URL_FREQUENCY, website_url_dict.items()),
                                      key=lambda item: len(item[1]),
                                      reverse=True)}
    global_logger.info(
        f'{len(url_filter_by_frequency)} websites with URLs appearing more than {DUMP_URL_FREQUENCY} times')

    dumping_dir = StorageLocation.result_dir() / "dump_website"
    dumping_detail_dir = dumping_dir / "detail"
    dumping_detail_dir.mkdir(parents=True, exist_ok=True)
    dumping_all_in_one_path = dumping_dir / "all_in_one.txt"
    all_in_one_res = ''

    def add_to_all_in_one(netloc_name: str, netloc_urls: list):
        nonlocal all_in_one_res
        if len(all_in_one_res) != 0:
            all_in_one_res += '\n' * 5
        all_in_one_res += f"[{len(netloc_urls)}] {netloc_name}" + '\n' + '-' * 30 + '\n'
        latest_urls = list(OrderedSet(netloc_urls)[-DUMP_URL_FREQUENCY:])  # save latest urls
        all_in_one_res += '\n'.join(latest_urls)

    for netloc_name, netloc_urls in url_filter_by_frequency.items():
        save_str('\n'.join(netloc_urls), dumping_detail_dir / netloc_name)
        add_to_all_in_one(netloc_name, netloc_urls)

    save_str(all_in_one_res, dumping_all_in_one_path)


def parse_single_cve(logger: logging.Logger, cve_row: dict) -> Optional[CveWithReferenceUrl]:
    # useful field:
    # [ id √, weaknesses √, vulnStatus √, references √, published √, metrics √, lastModified √, descriptions √ ]
    # vulnStatus: {'Deferred', 'Undergoing Analysis', 'Awaiting Analysis', 'Analyzed', 'Modified', 'Rejected', 'Received'}
    if (cve_row['vulnStatus'] not in ['Analyzed', 'Modified']) or ('weaknesses' not in cve_row):
        return

    cve_id = cve_row['id']
    cwe_list = extract_cwe_ids(cve_row['weaknesses'])
    if len(cwe_list) == 0:
        return

    description = extract_description(cve_row['descriptions'])
    publish_date = cve_row['published']
    last_modify_date = cve_row['lastModified']
    cvss_metric = extract_cvss_metrics(logger, cve_row['metrics'])
    references = filter_duplicate([i['url'] for i in cve_row['references']])
    extracted_reference_url = filter_duplicate(mining_commit_urls_from_reference_urls(logger, references))
    if DUMP_URL_FLAG:
        process_name = current_process().name
        if process_name == 'MainProcess':
            ALL_CVE_REFERENCE_URL.extend(references)
        else:
            raise Exception(
                "DUMP_URL MODE should only running in debug mode: (multiprocessing_apply_data_with_logger(debug=True))")

    return CveWithReferenceUrl(
        cve_id, cwe_list, description, publish_date, last_modify_date, extracted_reference_url,
        cvss_metric.cvss_vector, cvss_metric.cvss_score, cvss_metric.cvss_severity, cvss_metric.cvss_3
    )

def extract_cve_info():
    nvd_cve_entries: list[dict] = read_json_from_local(all_cve_from_nvd_json_path)

    global_logger.info(f'extracting cve info, reference URLs and find potential commit from {len(nvd_cve_entries)} CVE entries')
    cve_with_reference_urls: list[Optional[CveWithReferenceUrl]] = multiprocessing_apply_data_with_logger(parse_single_cve,
                                                                                                          nvd_cve_entries,
                                                                                                          debug=DUMP_URL_FLAG)
    global_logger.info(f'extracting cve info done!')
    cve_with_reference_urls: list[CveWithReferenceUrl] = list(
        filter(lambda x: x is not None and len(x.reference_urls) != 0, cve_with_reference_urls))
    global_logger.info(
        f'filter out cve entries with no reference url [{len(nvd_cve_entries)} -> {len(cve_with_reference_urls)}]')

    global_logger.info(f'save result to {cve_with_reference_url_json_path}')
    save_marshmallow_dataclass_to_json_file(CveWithReferenceUrl, cve_with_reference_url_json_path, cve_with_reference_urls)

    if DUMP_URL_FLAG:
        dump_url()


if __name__ == '__main__':
    extract_cve_info()
