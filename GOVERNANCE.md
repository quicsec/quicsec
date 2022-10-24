# QuicSec Governance

This document defines the project governance for QuicSec.

## Overview

The QuicSec community is committed  to building an an open and inclusive community where anyone can contribute to building a secure and pluggable HTTP3 middleware.
The community is governed by this document which defines how all members should work together in order to successfully achieve this goal.

## Code of Conduct

The QuicSec community abides by this [code of conduct](CODE_OF_CONDUCT.md).

## Community Roles

* **Users:** Members that engage with the QuicSec community via any medium (Slack, GitHub, Discord, mailing lists, etc.).
* **Contributors:** Contribute to the QuicSec project (source code, documentation, website content, code reviews, responding to issues, participating in proposal discussions, social media management, or any other effort that advances the evolution and adoption of the project).
* **Maintainers**: Responsible for the overall health and direction of the project. They are the final reviewers of PRs and responsible for QuicSec releases.

### Contributors

Anyone can contribute to the project (e.g. open a PR) as long as they follow the
guidelines in [CONTRIBUTING.md](CONTRIBUTING.md).

Frequent contributors to the project can become members of the [quicsec Github](https://github.com/quicsec) organization and receive write access to the repository.
Write access is required to trigger re-runs of workflows in [Github Actions](https://docs.github.com/en/actions/managing-workflow-runs/re-running-a-workflow).
Becoming a member of the quicsec Github organization does not come with additional responsibilities for the contributor, but simplifies the contributing process.
To become a member, you may [open an issue](https://github.com/quicsec/quicsec/issues/new?template=membership.md&title=REQUEST%3A%20New%20membership%20for%20%3Cyour-GH-handle%3E) and your membership needs to be approved by two maintainers: approval is indicated by leaving a `+1` comment.

#### Removal From QuicSec GitHub Organization

If a contributor is not active for a duration of 12 months (no contribution of any kind), they may be removed from the QuicSec Github organization.
In case of privilege abuse (members receive write access to the organization), any maintainer can decide to disable write access temporarily for the member.
Within the next 2 weeks, the maintainer must either restore the member's privileges, or remove the member from the organization.
The latter requires approval from at least one other maintainer, which must be obtained publicly either on Github or Slack.

### Maintainers

The list of current maintainers can be found in
[MAINTAINERS.md](MAINTAINERS.md).

While anyone can review a PR and is encouraged to do so, only maintainers are allowed to merge the PR.
To maintain velocity, only one maintainer's approval is required to merge a given PR.
In case of a disagreement between maintainers, a vote should be called (on Github or Slack) and a simple majority is required in order for the PR to be merged.

#### Adding and Removing Maintainers

New maintainers must be nominated from contributors by an existing maintainer and must be elected by a [supermajority](#supermajority) of the current maintainers.
Likewise, maintainers can be removed by a supermajority of the maintainers or can resign by notifying the maintainers.

### Supermajority

A supermajority is defined as two-thirds of members in a group.

## Code of Conduct

The code of conduct is overseen by the QuicSec project maintainers.
Possible code of conduct violations should be emailed to the project maintainers at _TODO create mailing list_.

If the possible violation is against one of the project maintainers that member
will be recused from voting on the issue.

## Updating Governance

All substantive changes in Governance require a supermajority vote of the
maintainers.