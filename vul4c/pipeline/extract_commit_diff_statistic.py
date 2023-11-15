from datetime import datetime
from typing import Callable
import matplotlib
from matplotlib.axes import Axes
from matplotlib.figure import Figure
import matplotlib.pyplot as plt
import seaborn as sns
from dataclasses import dataclass
from vul4c.git_platform.common import CveWithCommitInfo
from vul4c.pipeline.extract_commit_diff_filter import GlobalFilter
from vul4c.util.logging_util import global_logger
from vul4c.util.storage import StorageLocation
import pandas as pd
import plotly.express as px

figure_result_dir = StorageLocation.result_dir() / "figure"
figure_result_dir.mkdir(parents=True,exist_ok=True)


def tree_map():
    d = {'torvalds/linux': 1673, 'wireshark': 322, 'ImageMagick': 321, 'tensorflow': 287, 'chromium': 285, 'gpac': 225,
         'android': 225, 'ffmpeg': 192, 'php/php-src': 171, 'xen-project/xen': 171, 'binutils-gdb': 152, 'vim': 149,
         'openssl': 125, 'qemu': 113, 'radareorg/radare2': 105, 'the-tcpdump-group/tcpdump': 96, 'FFmpeg': 95,
         'ArtifexSoftware/ghostpdl': 73, 'freetype/freetype2': 49, 'jerryscript-project/jerryscript': 45}
    data = {
        'name': map(lambda x: x.split('/')[-1], list(d.keys())),
        'cnt': list(d.values())
    }

    df = pd.DataFrame(data)

    fig = px.treemap(df, path=['name'], values='cnt',
                     color='cnt',
                     color_continuous_scale='RdBu', )
    fig.update_layout(width=800,
                      height=800, )

    fig.show()


def debug(msg):
    global_logger.debug(str(msg))

def print_quantile(data: list):
    data_series = pd.Series(data)
    percentiles = [0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 0.95, 0.96, 0.97, 0.98, 0.99]
    percentile_values = data_series.quantile(percentiles)
    for percentile, value in zip(percentiles, percentile_values):
        debug(f"{int(percentile * 100)}% :{value}")


def calculate_3_sigma(data: list) -> tuple[float, float]:
    df = pd.DataFrame(data)
    mean = df.mean().item()
    std = df.std().item()
    lower_bound = (mean - 3 * std)
    upper_bound = (mean + 3 * std)
    return int(lower_bound), int(upper_bound)

def calculate_2_sigma(data: list) -> tuple[float, float]:
    df = pd.DataFrame(data)
    mean = df.mean().item()
    std = df.std().item()
    lower_bound = (mean - 2 * std)
    upper_bound = (mean + 2 * std)
    return int(lower_bound), int(upper_bound)

def boxplot(data: list, save_name: str):
    debug(save_name)
    pd.DataFrame(data).describe()
    print_quantile(data)
    sns.boxplot(y=data, orient='v').set_title(save_name)
    plt.savefig(figure_result_dir / f"{save_name}.svg")
    global_logger.info(f'3 sigma for {save_name} {calculate_3_sigma(data)}')
    global_logger.info(f'2 sigma for {save_name} {calculate_2_sigma(data)}')


@dataclass
class CommitMetrics:
    hash: str
    git_url: str
    file_cnt: int
    vul_cnt: int
    non_vul_cnt: int


@dataclass
class SimpleCve:
    cve_id: str
    publish_date: str
    cwe_ids: list


@dataclass
class RepositoryMetrics:
    repo_name: str
    cve_cnt: int
    commit_cnt: int
    vul_cnt: int
    non_vul_cnt: int
    commits: list[CommitMetrics]
    cves: list[SimpleCve]


class MetricsGlobalFilter(GlobalFilter):
    """
        collecting statistical information on dataset
    """

    def extract_cve_date(self, time_str: str) -> str:
        time = datetime.strptime(time_str, "%Y-%m-%dT%H:%M:%S.%f")
        return f"{time.year}-{time.month}"

    def get_monthly_cve_cnt(self, cve_cnt: dict) -> tuple[list, list]:
        def concat_year_month(year_month: str):
            year, month = year_month.split('-')
            return year * 100 + month

        month_cve_cnt = dict(sorted(cve_cnt.items(), key=lambda x: concat_year_month(x[0]), reverse=True))
        return list(month_cve_cnt.keys()), list(month_cve_cnt.values())

    def get_yearly_cve_cnt(self, cve_cnt: dict):
        new_cve_cnt = {}
        for k, v in cve_cnt.items():
            year = k.split('-')[0]
            new_cve_cnt.setdefault(year, 0)
            new_cve_cnt[year] += v
        year_cve_cnt = dict(sorted(new_cve_cnt.items(), key=lambda x: int(x[0]), reverse=True))
        return list(year_cve_cnt.keys()), list(year_cve_cnt.values())

    def year_and_month_cve_report(self, cve_cnt: dict):
        month_cve_cnt = self.get_monthly_cve_cnt(cve_cnt)
        year_cve_cnt = self.get_yearly_cve_cnt(cve_cnt)
        fig: Figure
        axes: list[Axes]
        fig, axes = plt.subplots(2, 1, figsize=(10, 8))
        self.simple_chart_plot(axes[0], month_cve_cnt[0][:24], month_cve_cnt[1][:24], 'Monthly CVE Report')
        self.simple_chart_plot(axes[1], year_cve_cnt[0], year_cve_cnt[1], 'Yearly CVE Report')
        fig.tight_layout()
        fig.savefig(figure_result_dir / "year_and_month_cve.svg")

    def simple_chart_plot(self, ax: matplotlib.axes.Axes, x: list, y: list, title: str):
        bar = ax.bar(x, y)
        ax.set_xticklabels(x, rotation=30, ha="right", rotation_mode="anchor", fontsize=8)
        ax.bar_label(bar, fontsize=6)
        ax.set_title(title)

    def get_sorted_repo_metric(self, repo_statistics: dict[str, RepositoryMetrics],
                               get_field: Callable[[RepositoryMetrics], int]) -> tuple[list[str], list[int]]:
        result: dict[str, int] = {}
        for k, v in repo_statistics.items():
            result[k] = get_field(v)
        sorted_result = dict(sorted(result.items(), key=lambda x: x[1], reverse=True))
        return list(sorted_result.keys()), list(sorted_result.values())

    def repo_commits_cnt(self, repo_statistics: dict[str, RepositoryMetrics], ax: matplotlib.axes.Axes):
        repo_names, repo_commits = self.get_sorted_repo_metric(repo_statistics, lambda x: len(x.commits))
        # get top-20 result
        self.simple_chart_plot(ax, repo_names[:20], repo_commits[:20], "Repository Commit")

    def repo_vul_func_cnt(self, repo_statistics: dict[str, RepositoryMetrics], ax: matplotlib.axes.Axes,
                          is_non_vul: bool = False):
        repo_names, func_cnt = self.get_sorted_repo_metric(repo_statistics,
                                                           lambda x: x.vul_cnt if not is_non_vul else x.non_vul_cnt)
        self.simple_chart_plot(ax, repo_names[:15], func_cnt[:15],
                               f'{"Non-" if is_non_vul else ""}Vulnerable Function Count')

    def repo_cve_cnt(self, repo_statistics: dict[str, RepositoryMetrics], ax: matplotlib.axes.Axes):
        repo_names, cve_cnt = self.get_sorted_repo_metric(repo_statistics, lambda x: x.cve_cnt)
        self.simple_chart_plot(ax, repo_names[:20], cve_cnt[:20], "Repository Related CVE")

    def repo_metrics_plot(self, repo_statistics: dict[str, RepositoryMetrics]):
        fig: Figure
        axes: list[Axes]
        fig, axes = plt.subplots(nrows=2, ncols=2, figsize=(10, 8))

        self.repo_cve_cnt(repo_statistics, axes[0][0])
        self.repo_commits_cnt(repo_statistics, axes[0][1])
        self.repo_vul_func_cnt(repo_statistics, axes[1][0])
        self.repo_vul_func_cnt(repo_statistics, axes[1][1], is_non_vul=True)

        fig.tight_layout()
        fig.savefig(figure_result_dir / "repo_metrics.svg")

    Color_Palette = ['#d22b26', '#d964a4', '#2e2eff', '#fdce7f', '#fef1a9', '#6aa2cb', '#9262a3', '#b57726', '#a7d671',
                     '#498d20']

    def cve_year_repo_cnt_plot(self, repo_statistics: dict[str, RepositoryMetrics], ax: Axes):
        top_repo_names, _ = self.get_sorted_repo_metric(repo_statistics, lambda x: x.cve_cnt)
        top_repo_names = top_repo_names[:10]  # top-10 repos

        cve_year_repo_cnt = {}
        Other_Key = "Other"

        for repo_name, repo in repo_statistics.items():
            for cve in repo.cves:
                cve_publish_year = self.extract_cve_date(cve.publish_date).split('-')[0]
                cve_year_repo_cnt.setdefault(cve_publish_year, {})
                cve_year_repo_cnt[cve_publish_year].setdefault(Other_Key, 0)
                if repo_name not in top_repo_names:
                    cve_year_repo_cnt[cve_publish_year][Other_Key] += 1
                    continue

                cve_year_repo_cnt[cve_publish_year].setdefault(repo_name, 0)
                cve_year_repo_cnt[cve_publish_year][repo_name] += 1

        possible_years = []
        for k, v in cve_year_repo_cnt.items():
            if sum(v.values()) > 20:
                possible_years.append(k)
        possible_years = list(sorted(possible_years, key=lambda x: int(x), reverse=True))
        years = possible_years

        top_repo_names.append(Other_Key)
        bar_heights = {
            label: [cve_year_repo_cnt[year][label] if label in cve_year_repo_cnt[year] else 0 for year in years] for
            label in top_repo_names}
        bottom = [0] * len(years)

        for idx, label in enumerate(bar_heights):
            color = 'gray' if idx == len(bar_heights) - 1 else self.Color_Palette[idx]
            ax.bar(years, bar_heights[label], label=label, bottom=bottom, color=color)
            bottom = [sum(x) for x in zip(bottom, bar_heights[label])]
        ax.set_xticklabels(years, fontsize=6)
        ax.set_title('Repository CVE Count Over The Years')
        legend = ax.legend()
        # for text in legend.get_texts():
        #     text.set_fontsize(8)

        debug(cve_year_repo_cnt)

    def get_top_cwe_and_plot(self, repo_statistics: dict[str, RepositoryMetrics], ax: Axes) -> list[str]:
        cwe_cnt = {}

        for repo_name, repo in repo_statistics.items():
            for cve in repo.cves:
                for cwe_id in cve.cwe_ids:
                    cwe_cnt.setdefault(cwe_id, 0)
                    cwe_cnt[cwe_id] += 1

        sorted_cwe_cnt = dict(sorted(cwe_cnt.items(), key=lambda x: x[1], reverse=True))
        TOP_CWE = 20
        sorted_cwe_names = list(sorted_cwe_cnt.keys())
        top_cwe_names = sorted_cwe_names[:TOP_CWE]
        debug(f'Top {TOP_CWE} CWE: all cwe count{sum(cwe_cnt.values())}')
        debug(str(dict(zip(top_cwe_names, list(sorted_cwe_cnt.values())[:TOP_CWE]))))
        self.simple_chart_plot(ax, top_cwe_names, list(sorted_cwe_cnt.values())[:TOP_CWE], f"Top {TOP_CWE} CWE")
        return top_cwe_names

    def cve_year_cwe_cnt_plot(self, repo_statistics: dict[str, RepositoryMetrics], sorted_cwe_names: list[str],
                              ax: Axes):
        cve_year_cwe_cnt = {}
        debug(sorted_cwe_names)
        if 'CWE-Other' in sorted_cwe_names:
            sorted_cwe_names.remove('CWE-Other')
        top_10_cwe_names = sorted_cwe_names[:10]
        Other_Key = "Other"

        for repo_name, repo in repo_statistics.items():
            for cve in repo.cves:
                cve_publish_year = self.extract_cve_date(cve.publish_date).split('-')[0]
                cve_year_cwe_cnt.setdefault(cve_publish_year, {})
                for cwe in cve.cwe_ids:
                    cve_year_cwe_cnt[cve_publish_year].setdefault(Other_Key, 0)
                    if cwe in top_10_cwe_names:
                        cve_year_cwe_cnt[cve_publish_year].setdefault(cwe, 0)
                        cve_year_cwe_cnt[cve_publish_year][cwe] += 1
                    else:
                        cve_year_cwe_cnt[cve_publish_year][Other_Key] += 1

        possible_years = []
        for k, v in cve_year_cwe_cnt.items():
            if sum(v.values()) > 20:
                possible_years.append(k)

        possible_years = list(sorted(possible_years, key=lambda x: int(x), reverse=True))
        years = possible_years
        top_10_cwe_names.append(Other_Key)
        bar_heights = {
            label: [cve_year_cwe_cnt[year][label] if label in cve_year_cwe_cnt[year] else 0 for year in years] for label
            in top_10_cwe_names}
        bottom = [0] * len(years)

        for idx, label in enumerate(bar_heights):
            color = 'gray' if idx == len(bar_heights) - 1 else self.Color_Palette[idx]
            ax.bar(years, bar_heights[label], label=label, bottom=bottom, color=color)
            bottom = [sum(x) for x in zip(bottom, bar_heights[label])]
        ax.set_xticklabels(years, fontsize=5)
        ax.set_title('Top10 CWE Count Over The Years')
        legend = ax.legend()

    def repo_cwe_cnt_plot(self, repo_statistics: dict[str, RepositoryMetrics], sorted_cwe_names: list[str], ax: Axes):
        top_repo_names, _ = self.get_sorted_repo_metric(repo_statistics, lambda x: x.cve_cnt)
        top_repo_names = top_repo_names[:10]  # top-10 repos
        if 'CWE-Other' in sorted_cwe_names:
            sorted_cwe_names.remove('CWE-Other')
        sorted_cwe_names = sorted_cwe_names[:10]
        CWE_Other = 'Other'

        repo_cwe_cnt = {}
        repo_bottoms = {}

        for repo_name in top_repo_names:
            cwe_cnt = {}
            for cve in repo_statistics[repo_name].cves:
                for cwe in cve.cwe_ids:
                    if cwe in sorted_cwe_names:
                        cwe_cnt.setdefault(cwe, 0)
                        cwe_cnt[cwe] += 1
                    else:
                        cwe_cnt.setdefault(CWE_Other, 0)
                        cwe_cnt[CWE_Other] += 1

            sorted_cwe_cnt = sorted(cwe_cnt.items(), key=lambda x: x[1], reverse=True)
            repo_cwe_cnt[repo_name] = dict(sorted_cwe_cnt)
            sorted_cwe_cnt = list(sorted_cwe_cnt)
            this_repo_cwe_height = {}

            for cwe_name in sorted_cwe_names:
                # calculate bottom
                sum_bottom = 0
                for cwe_inner_name, cve_cnt in sorted_cwe_cnt:
                    if cwe_inner_name == cwe_name:
                        break
                    sum_bottom += cve_cnt
                this_repo_cwe_height[cwe_name] = sum_bottom
            repo_bottoms[repo_name] = this_repo_cwe_height

        sorted_cwe_names.append(CWE_Other)
        bar_heights = {
            cwe_name: [repo_cwe_cnt[repo][cwe_name] if cwe_name in repo_cwe_cnt[repo] else 0 for repo in top_repo_names]
            for cwe_name in sorted_cwe_names}
        bar_bottoms = {
            cwe_name: [repo_bottoms[repo][cwe_name] if cwe_name in repo_bottoms[repo] else 0 for repo in top_repo_names]
            for cwe_name in sorted_cwe_names}

        for idx, label in enumerate(bar_heights):
            color = 'gray' if idx == len(bar_heights) - 1 else self.Color_Palette[idx]
            debug(bar_heights[label])
            debug(bar_bottoms[label])
            ax.bar(top_repo_names, bar_heights[label], label=label, bottom=bar_bottoms[label], color=color)

        ax.set_xticklabels(top_repo_names, rotation=30, ha="right", rotation_mode="anchor", fontsize=7)
        ax.legend()

    def cwe_repo_cnt_plot(self, repo_statistics: dict[str, RepositoryMetrics], sorted_cwe_names: list[str], ax: Axes):
        top_repo_names, _ = self.get_sorted_repo_metric(repo_statistics, lambda x: x.cve_cnt)
        top_repo_names = top_repo_names[:10]  # top-10 repos
        if 'CWE-Other' in sorted_cwe_names:
            sorted_cwe_names.remove('CWE-Other')
        sorted_cwe_names = sorted_cwe_names[:10]

        cwe_repo_cnt = {}
        for repo_statistic in repo_statistics.values():
            repo_name = repo_statistic.repo_name

            for cve in repo_statistic.cves:

                for cwe_id in cve.cwe_ids:
                    if cwe_id not in sorted_cwe_names:
                        continue
                    cwe_repo_cnt.setdefault(cwe_id, {})
                    cwe_repo_cnt[cwe_id].setdefault(repo_name, 0)
                    cwe_repo_cnt[cwe_id][repo_name] += 1

        colors = ["#ab71af", "#6baddf", "#9cd274", "#e093bb", "#da8868", "#f9b269", "#61737b", "#3d8ad9", "#d8a31a",
                  "#4c8580", "#bd5405", "#d8b4ff", "#ffce53", "#774af9"]
        colors_mapping = {'torvalds/linux': "#f17078",
                          "Other": "#929292",
                          'android': '#38df88',
                          'tensorflow': '#ff8908',
                          'chromium': '#3780f0',
                          'php/php-src': '#7b7fb5',
                          'ffmpeg': '#007607',
                          }
        color_idx = 0

        def get_color(repo_name: str):
            nonlocal colors_mapping, color_idx
            if repo_name not in colors_mapping:
                colors_mapping[repo_name] = colors[color_idx]
                color_idx += 1
            return colors_mapping[repo_name]

        sorted_cwe_repo_cnt = {}
        repo_cnt_dict: dict
        for cwe_id in sorted_cwe_names:
            repo_cnt_dict = cwe_repo_cnt[cwe_id]
            sorted_repo_cnt = sorted(repo_cnt_dict.items(), key=lambda x: x[1], reverse=True)
            sorted_result = dict(sorted_repo_cnt[:5])
            other_repo_cwe_cnt_sum = sum([i[1] for i in sorted_repo_cnt[5:]])
            sorted_result['Other'] = other_repo_cwe_cnt_sum
            sum_cnt = sum(sorted_result.values())
            # new_sorted_result = {k: (v, round(v / sum_cnt * 100, 2), get_color(k)) for k, v in sorted_result.items()}
            new_sorted_result = {k: v for k, v in sorted_result.items()}

            sorted_cwe_repo_cnt[cwe_id] = new_sorted_result

        debug('CWE top 10 rpeo')
        debug(sorted_cwe_repo_cnt)
        debug(colors_mapping)

    def cwe_statistic(self, repo_statistics: dict[str, RepositoryMetrics]):
        fig: Figure
        axes: list[Axes]
        fig, axes = plt.subplots(nrows=3, ncols=2, figsize=(10, 8))

        sorted_cwe_names = self.get_top_cwe_and_plot(repo_statistics, axes[0][0])
        self.cve_year_repo_cnt_plot(repo_statistics, axes[0][1], )
        self.cve_year_cwe_cnt_plot(repo_statistics, sorted_cwe_names, axes[1][0])
        self.repo_cwe_cnt_plot(repo_statistics, sorted_cwe_names, axes[1][1])
        self.cwe_repo_cnt_plot(repo_statistics, sorted_cwe_names, axes[2][0])

        fig.tight_layout()
        fig.savefig(figure_result_dir / 'cwe_metrics.svg' )

    def filter(self, cve_list: list[CveWithCommitInfo]) -> list[CveWithCommitInfo]:
        result_cve = []

        cve_cnt = 0
        all_commit_diff_cnt = []  # calculate the average diff number of commits
        cve_average_commit_cnt = []  # average commit count for one CVE
        vul_line_cnt = []  #  average number of lines of the vul functions
        non_vul_line_cnt = []  # average number of lines of the non-vul functions
        non_vul_line_per_file_cnt = []  # average number of lines of the non-vul functions in one file
        repo_statistics: dict[str, RepositoryMetrics] = {}
        cve_date_distribution = {}
        cve_year_cwe_cnt = {}
        year_commit_count = {}
        year_cve_count = {}
        year_repo_commit_count = {}
        cwe_all_in_one = set()
        commit_cnt = 0
        linux_test = { }
        memory_related_cwe = ["CWE-119", "CWE-125", "CWE-787", "CWE-476", "CWE-20", "CWE-416", "CWE-190"]
        cwe_cnt = 0
        memory_cwe_cnt = 0


        for cve in cve_list:
            commit_infos = []
            # global_logger.debug(f'{cve.cve_id} {cve.cwe_ids}')
            cve_year_month = self.extract_cve_date(cve.publish_date)
            year = cve_year_month.split('-')[0]
            cve_date_distribution.setdefault(cve_year_month, 0)
            cve_date_distribution[cve_year_month] += len(cve.commits)

            cve_year_cwe_cnt.setdefault(year, {})

            for cwe in cve.cwe_ids:
                cve_year_cwe_cnt[year].setdefault(cwe, 0)
                cve_year_cwe_cnt[year][cwe] += 1
                cwe_all_in_one.add(cwe)
                cwe_cnt += 1
                if cwe in memory_related_cwe:
                    memory_cwe_cnt += 1

            commit_cnt += len(cve.commits)
            year_commit_count.setdefault(year, 0)
            year_cve_count.setdefault(year, 0)
            year_cve_count[year] += 1
            year_repo_commit_count.setdefault(year, { })
            year_commit_count[year] += len(cve.commits)
            for commit in cve.commits:
                repo_name = commit.repo_name
                if repo_name == 'torvalds/linux':
                    linux_test.setdefault(year, 0)
                    linux_test[year] += 1
                year_repo_commit_count[year].setdefault(repo_name,0)
                year_repo_commit_count[year][repo_name] += 1

                repo_statistics.setdefault(repo_name, RepositoryMetrics(repo_name, 0, 0, 0, 0, [], []))
                # global_logger.debug(commit)

                vul_func_cnt_in_commit = 0
                non_vul_func_cnt_in_commit = 0
                commit_diff_cnt = 0
                for file in commit.files:
                    vul_func_cnt_in_commit += len(file.vulnerable_functions)
                    non_vul_func_cnt_in_commit += len(file.non_vulnerable_functions)
                    for v in file.vulnerable_functions:
                        commit_diff_cnt += len(v.diff_line_info['deleted_lines']) + len(v.diff_line_info['added_lines'])
                        vul_line_cnt.append(len(v.func_after.split('\n')))

                    for v in file.non_vulnerable_functions:
                        non_vul_line_cnt.append(len(v.func.split('\n')))
                    non_vul_line_per_file_cnt.append(
                        sum([len(f.func.split('\n')) for f in file.non_vulnerable_functions]))

                all_commit_diff_cnt.append(commit_diff_cnt)

                old_metrics = repo_statistics[repo_name]
                old_metrics.commit_cnt += 1
                old_metrics.vul_cnt += vul_func_cnt_in_commit
                old_metrics.non_vul_cnt += non_vul_func_cnt_in_commit
                old_metrics.commits.append(
                    CommitMetrics(commit.commit_hash, commit.git_url, len(commit.files), vul_func_cnt_in_commit,
                                  non_vul_func_cnt_in_commit))
                if len(old_metrics.cves) > 0 and old_metrics.cves[-1].cve_id == cve.cve_id:  # duplicate add
                    pass
                else:
                    old_metrics.cve_cnt += 1
                    old_metrics.cves.append(SimpleCve(cve.cve_id, cve.publish_date, cve.cwe_ids))
                repo_statistics[repo_name] = old_metrics

            cve_average_commit_cnt.append(len(cve.commits))

        self.repo_metrics_plot(repo_statistics)
        print(all_commit_diff_cnt)
        print(cve_average_commit_cnt)
        print(vul_line_cnt)
        print(non_vul_line_per_file_cnt)
        print(cve_date_distribution)
        print(f'Total Repo:{len(repo_statistics)}')
        print(f'Total CVE id:{len(cve_list)}')
        print(f'Total CWE id:{len(cwe_all_in_one)}')
        print(f'Year CWE {cve_year_cwe_cnt}')
        print(f'Total Commits {commit_cnt}')
        print(f'Every year commit {dict(sorted(year_commit_count.items(), key=lambda x: int(x[0]), reverse=False))}')
        print(f'Every year cve {dict(sorted(year_cve_count.items(), key=lambda x: int(x[0]), reverse=False))}')
        repo_top_20, repo_top20_cve_cnt = self.get_sorted_repo_metric(repo_statistics, lambda x: x.cve_cnt)
        repo_top_20 = repo_top_20[:20]
        repo_top20_cve_cnt = repo_top20_cve_cnt[:20]
        print('Repo Top20', dict(zip(repo_top_20, repo_top20_cve_cnt)))
        print('memory-related cwe',memory_cwe_cnt, cwe_cnt)

        self.year_and_month_cve_report(cve_date_distribution)
        boxplot(all_commit_diff_cnt, 'commit_boxplot')
        boxplot(cve_average_commit_cnt, 'one_cve_need_commit_cnt_boxplot')
        boxplot(vul_line_cnt, 'vulnerable_function_lines_boxplot')
        boxplot(non_vul_line_cnt, 'non_vulnerable_function_lines_boxplot')
        boxplot(non_vul_line_per_file_cnt, 'non_vulnerable_function_per_file_lines_boxplot')

        self.cwe_statistic(repo_statistics)
        self.linux(repo_statistics)
        for k,v in year_repo_commit_count.items():
            print(k)
            for i,j in v.items():
                if j > 10:
                    print(i,j)
        print(len(repo_statistics['torvalds/linux'].commits))
        print(linux_test)
        return cve_list

    def linux(self,repo_statistics: dict[str, RepositoryMetrics]):
        linux = repo_statistics['torvalds/linux']
        cve_each_year = { }
        for cve in linux.cves:
            year =  self.extract_cve_date(cve.publish_date).split('-')[0]
            cve_each_year.setdefault(year ,0 )
            cve_each_year[year] +=1

        print(cve_each_year)