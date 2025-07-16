package lpad

import (
	"errors"
	"strings"
)

var weirdPrefixes = []string{
	// Launchpad failed to handle this one in getByUrl.
	"bzr+ssh://bazaar.launchpad.net/+branch/",
}

// Branch returns a branch for the provided URL. The URL can be in
// the short form lp: notation, or the web address rooted at
// http://bazaar.launchpad.net/
func (root *Root) Branch(burl string) (*Branch, error) {
	// getByUrl doesn't like escaped URLs.
	burl = strings.Replace(burl, "%2B", "+", -1)
	for _, prefix := range weirdPrefixes {
		if strings.HasPrefix(burl, prefix) {
			burl = "lp:" + burl[len(prefix):]
			break
		}
	}
	v, err := root.Location("/branches").Get(Params{"ws.op": "getByUrl", "url": burl})
	if err != nil {
		return nil, err
	}
	return &Branch{v}, nil
}

// The Branch type represents a project in Launchpad.
type Branch struct {
	*Value
}

// Id returns the shortest version for the branch name. If the branch
// is the development focus for a project, a lp:project form will be
// returned. If it's the development focus for a series, then a
// lp:project/series is returned. Otherwise, the unique name for the
// branch in the form lp:~user/project/branch-name is returned.
func (b *Branch) Id() string {
	return b.StringField("bzr_identity")
}

// RevisionCount returns the revision number of the tip of the branch
func (b *Branch) RevisionCount() int {
	return b.IntField("revision_count")
}

// UniqueName returns the unique branch name, in the
// form lp:~user/project/branch-name.
func (b *Branch) UniqueName() string {
	return b.StringField("unique_name")
}

// Owner returns the Person that owns this branch.
func (b *Branch) Owner() (*Person, error) {
	p, err := b.Link("owner_link").Get(nil)
	if err != nil {
		return nil, err
	}
	return &Person{p}, nil
}

// OwnerName returns the name from the owner of this branch.
func (b *Branch) OwnerName() string {
	un := b.UniqueName()
	if len(un) > 0 && un[0] == '~' {
		for i := 0; i < len(un); i++ {
			if un[i] == '/' {
				return un[1:i]
			}
		}
	}
	panic("can't find owner name in unique_name: " + un)
}

// ProjectName returns the name for the project this branch is part of.
func (b *Branch) ProjectName() string {
	un := b.UniqueName()
	if len(un) > 0 && un[0] == '~' {
		var i, j int
		for i = 0; i < len(un); i++ {
			if un[i] == '/' {
				break
			}
		}
		i++
		if i < len(un) {
			for j = i; j < len(un); j++ {
				if un[j] == '/' {
					break
				}
			}
			return un[i:j]
		}
	}
	panic("can't find project name in unique_name: " + un)
}

// WebPage returns the URL for accessing this branch in a browser.
func (b *Branch) WebPage() string {
	return b.StringField("web_link")
}

// LandingCandidates returns a list of all the merge proposals that
// have this branch as the target of the proposed change.
func (b *Branch) LandingCandidates() (*MergeProposalList, error) {
	v, err := b.Link("landing_candidates_collection_link").Get(nil)
	if err != nil {
		return nil, err
	}
	return &MergeProposalList{v}, nil
}

// LandingTargets returns a list of all the merge proposals that
// have this branch as the source of the proposed change.
func (b *Branch) LandingTargets() (*MergeProposalList, error) {
	v, err := b.Link("landing_targets_collection_link").Get(nil)
	if err != nil {
		return nil, err
	}
	return &MergeProposalList{v}, nil
}

type MergeStub struct {
	Description   string
	CommitMessage string
	NeedsReview   bool
	Target        *Branch
	PreReq        *Branch
}

// ProposeMerge proposes this branch for merging on another branch by
// creating the respective merge proposal.
func (b *Branch) ProposeMerge(stub *MergeStub) (mp *MergeProposal, err error) {
	if stub.Target == nil {
		return nil, errors.New("Missing target branch")
	}
	params := Params{
		"ws.op":         "createMergeProposal",
		"target_branch": stub.Target.AbsLoc(),
	}
	if stub.Description != "" {
		params["initial_comment"] = stub.Description
	}
	if stub.CommitMessage != "" {
		params["commit_message"] = stub.CommitMessage
	}
	if stub.NeedsReview {
		params["needs_review"] = "true"
	} else {
		params["needs_review"] = "false"
	}
	if stub.PreReq != nil {
		params["prerequisite_branch"] = stub.PreReq.AbsLoc()
	}
	v, err := b.Post(params)
	if err != nil {
		return nil, err
	}
	return &MergeProposal{v}, nil
}

type MergeProposal struct {
	*Value
}

// Description returns the detailed description of the changes being
// proposed in the source branch of the merge proposal.
func (mp *MergeProposal) Description() string {
	return mp.StringField("description")
}

// SetDescription changes the detailed description of the changes being
// proposed in the source branch of the merge proposal.
func (mp *MergeProposal) SetDescription(description string) {
	mp.SetField("description", description)
}

type MergeProposalStatus string

const (
	StWorkInProgress MergeProposalStatus = "Work in progress"
	StNeedsReview    MergeProposalStatus = "Needs review"
	StApproved       MergeProposalStatus = "Approved"
	StRejected       MergeProposalStatus = "Rejected"
	StMerged         MergeProposalStatus = "Merged"
	StFailedToMerge  MergeProposalStatus = "Code failed to merge"
	StQueued         MergeProposalStatus = "Queued"
	StSuperseded     MergeProposalStatus = "Superseded"
)

// Status returns the current status of the merge proposal.
// E.g. Needs Review, Work In Progress, etc.
func (mp *MergeProposal) Status() MergeProposalStatus {
	return MergeProposalStatus(mp.StringField("queue_status"))
}

// SetStatus changes the current status of the merge proposal.
func (mp *MergeProposal) SetStatus(status MergeProposalStatus) error {
	_, err := mp.Post(Params{"ws.op": "setStatus", "status": string(status)})
	return err
}

// CommitMessage returns the commit message to be used when merging
// the source branch onto the target branch.
func (mp *MergeProposal) CommitMessage() string {
	return mp.StringField("commit_message")
}

// SetCommitMessage changes the commit message to be used when
// merging the source branch onto the target branch.
func (mp *MergeProposal) SetCommitMessage(msg string) {
	mp.SetField("commit_message", msg)
}

// Email returns the unique email that may be used to add new comments
// to the merge proposal conversation.
func (mp *MergeProposal) Email() string {
	return mp.StringField("address")
}

// Source returns the source branch that has additional code to land.
func (mp *MergeProposal) Source() (*Branch, error) {
	v, err := mp.Link("source_branch_link").Get(nil)
	if err != nil {
		return nil, err
	}
	return &Branch{v}, nil
}

// Target returns the branch where code will land on once merged.
func (mp *MergeProposal) Target() (*Branch, error) {
	v, err := mp.Link("target_branch_link").Get(nil)
	if err != nil {
		return nil, err
	}
	return &Branch{v}, nil
}

// PreReq returns the branch is the base (merged or not) for the code
// within the target branch.
func (mp *MergeProposal) PreReq() (*Branch, error) {
	v, err := mp.Link("prerequisite_branch_link").Get(nil)
	if err != nil {
		return nil, err
	}
	return &Branch{v}, nil
}

// WebPage returns the URL for accessing this merge proposal
// in a browser.
func (mp *MergeProposal) WebPage() string {
	return mp.StringField("web_link")
}

type ProposalVote string

const (
	VoteNone        ProposalVote = ""
	VoteApprove     ProposalVote = "Approve"
	VoteNeedsFixing ProposalVote = "Needs Fixing"
	VoteNeedsInfo   ProposalVote = "Needs Information"
	VoteAbstain     ProposalVote = "Abstain"
	VoteDisapprove  ProposalVote = "Disapprove"
	VoteResubmit    ProposalVote = "Resubmit"
)

// AddComment adds a new comment to mp.
func (mp *MergeProposal) AddComment(subject, message string, vote ProposalVote, reviewType string) error {
	params := Params{
		"ws.op":   "createComment",
		"subject": subject,
	}
	if message != "" {
		params["content"] = message
	}
	if vote != VoteNone {
		params["vote"] = string(vote)
	}
	if reviewType != "" {
		params["review_type"] = reviewType
	}
	_, err := mp.Post(params)
	return err
}

// The MergeProposalList represents a list of MergeProposal objects.
type MergeProposalList struct {
	*Value
}

// For iterates over the list of merge proposals and calls f for each one.
// If f returns a non-nil error, iteration will stop and the error will be
// returned as the result of For.
func (list *MergeProposalList) For(f func(t *MergeProposal) error) error {
	return list.Value.For(func(v *Value) error {
		return f(&MergeProposal{v})
	})
}
