# Contributing to LunLink

Contributions are welcome: reports of problems, fixes, and improvements.
（中文说明见本文末尾。）

## Reporting problems

* Say which version of macOS and which kind of Mac you use, what the iSCSI
  server is (make and model, or the software that provides the target), and
  what you did.
* The log of the daemon helps a great deal: `~/Library/Logs/LunLink/iscsid.log`
  (in the application: *Settings → Show Log*). Run `iscsid -d` for more detail.
* **Look through a log before you post it.** It names your targets and the
  addresses of your servers. Never post CHAP secrets.
* A problem that bears on security is better reported in private: use
  *Report a vulnerability* on the *Security* tab of the repository instead of
  a public issue.

## Changing the code

* Build with `make` and run `make test` before you propose a change. The
  tests attach disks to the system for real (from mock targets on this Mac);
  they keep their configuration apart from yours. Nothing but the Xcode
  Command Line Tools is needed.
* The user interface comes in English and Simplified Chinese. A string that
  the application shows needs both: the English original in the code and its
  translation in `Source/User/App/Resources/zh-Hans.lproj`.
  `Tests/check_localization.py` tells what is missing.
* Keep to the style of the code around your change.
* A change to how disks are attached, or to how sessions are recovered,
  should come with a test.

## Licensing of contributions

LunLink is distributed under the BSD 2-Clause License (see
[LICENSE.md](LICENSE.md)). By submitting a contribution you agree that it is
distributed under the same license, and you state that you have the right to
submit it: that it is your own work, or that its license permits this use.

* New files start with a copyright line for the contributors of LunLink and
  an SPDX identifier, as the existing files do.
* Files that contain code of the original project keep the copyright notice
  of the original (see [NOTICE.md](NOTICE.md)). Do not remove it.
* Do not add code under a license that is incompatible with the BSD 2-Clause
  License, and say so in `NOTICE.md` when you add third-party material.

---

## 中文说明

欢迎反馈问题、提交修复和改进。

* **反馈问题**时请说明 macOS 版本、Mac 型号、iSCSI 服务器的品牌型号（或提供目标的软件），以及操作步骤。守护进程的日志很有帮助：`~/Library/Logs/LunLink/iscsid.log`（应用内：“设置 → 显示日志”）。**贴日志前请先看一遍**：里面有目标名称和服务器地址；任何时候都不要贴 CHAP 密码。涉及安全的问题请通过仓库 *Security* 页的 *Report a vulnerability* 私下报告。
* **修改代码**前后请执行 `make` 和 `make test`。界面文案需要中英文齐全，`Tests/check_localization.py` 会指出缺失的条目。
* **许可**：提交即表示您同意以 BSD 2-Clause 许可证发布该贡献，并确认您有权提交。新文件以 LunLink 贡献者的版权行和 SPDX 标识开头；含有原项目代码的文件必须保留原作者的版权声明（见 [NOTICE.md](NOTICE.md)）。
