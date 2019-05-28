package okta

import (
	"errors"
	"fmt"
	"net/url"
	"time"
)

const (
	groupRuleStatus            = "ACTIVE"
	groupRuleTypeFilter        = "group_rule"
	groupRuleNameFilter        = "q"
	groupRuleLastUpdatedFilter = "lastUpdated"
	groupRuleExpressionType    = "urn:okta:expression:1.0"
)

type GroupRuleService service

type GroupRule struct {
	ID          string    `json:"id"`
	Status      string    `json:"staus"`
	Name        string    `json:"name"`
	Created     time.Time `json:"created"`
	LastUpdated time.Time `json:"lastUpdated"`
	Type        string    `json:"type"`
	Conditions  struct {
		People struct {
			Users struct {
				Exclude []string `json:"exclude"`
			}
			Groups struct {
				Exclude []string `json:"exclude"`
			}
		}
		Expression struct {
			Value string `json:"value"` // f.e. "user.productGroup==\"pricing\"",
			Type  string `json:"type"`  //defaults to "urn:okta:expression:1.0"
		}
	}
	Actions struct {
		AssignUserToGroups struct {
			GroupIds []string `json:"groupIds"`
		}
	}
}

func (g GroupRule) String() string {
	// return Stringify(g)
	return fmt.Sprintf("GroupRoule:(ID: {%v} - Type: {%v} - GroupRule Name: {%v})\n", g.ID, g.Type, g.Name)
}

type GroupRuleFilterOptions struct {
	// This will be built by internal - may not need to export
	FilterString  string   `url:"filter,omitempty"`
	NextURL       *url.URL `url:"-"`
	GetAllPages   bool     `url:"-"`
	NumberOfPages int      `url:"-"`
	Limit         int      `url:"limit,omitempty"`

	NameStartsWith     string `url:"q,omitempty"`
	GroupRuleTypeEqual string `url:"-"`

	LastUpdated           dateFilter `url:"-"`
	LastMembershipUpdated dateFilter `url:"-"`
}
type newGroupRule struct {
	Name       string `json:"name"`
	Conditions struct {
		Expression struct {
			Value string `json:"value"`
			Type  string `json:"type"`
		}
	}
}

// ListWithFilter - Method to list group rules by filters like name
func (g *GroupRuleService) ListWithFilter(opt *GroupRuleFilterOptions) ([]GroupRule, *Response, error) {
	pagesRetrieved := 0
	var gr string
	var err error

	if opt.NextURL != nil {
		gr = opt.NextURL.String()
	} else {
		if opt.GroupRuleTypeEqual != "" {
			opt.FilterString = appendToFilterString(opt.FilterString, groupRuleTypeFilter, FilterEqualOperator, opt.GroupRuleTypeEqual)
		}
		if (!opt.LastMembershipUpdated.Value.IsZero()) && (opt.LastMembershipUpdated.Operator != "") {
			opt.FilterString = appendToFilterString(opt.FilterString, groupLastMembershipUpdatedFilter, opt.LastMembershipUpdated.Operator, opt.LastMembershipUpdated.Value.UTC().Format(oktaFilterTimeFormat))
		}
		if (!opt.LastUpdated.Value.IsZero()) && (opt.LastUpdated.Operator != "") {
			opt.FilterString = appendToFilterString(opt.FilterString, groupLastUpdatedFilter, opt.LastUpdated.Operator, opt.LastUpdated.Value.UTC().Format(oktaFilterTimeFormat))
		}
		if opt.Limit == 0 {
			opt.Limit = defaultLimit
		}
		gr, err = addOptions("grouprules", opt)
		if err != nil {
			return nil, nil, err
		}
	}
	req, err := g.client.NewRequest("GET", gr, nil)
	if err != nil {
		return nil, nil, err
	}
	grouprules := make([]GroupRule, 1)
	resp, err := g.client.Do(req, &grouprules)
	if err != nil {
		return nil, resp, err
	}
	pagesRetrieved++

	if (opt.NumberOfPages > 0 && pagesRetrieved < opt.NumberOfPages) || opt.GetAllPages {

		for {

			if pagesRetrieved == opt.NumberOfPages {
				break
			}
			if resp.NextURL != nil {
				var groupRulePage []GroupRule
				pageOption := new(GroupRuleFilterOptions)
				pageOption.NextURL = resp.NextURL
				pageOption.NumberOfPages = 1
				pageOption.Limit = opt.Limit

				groupRulePage, resp, err = g.ListWithFilter(pageOption)
				if err != nil {
					return grouprules, resp, err
				}
				grouprules = append(grouprules, groupRulePage...)
				pagesRetrieved++

			} else {
				break
			}
		}
	}
	return grouprules, resp, err
}

// Add creates a new Grouprule based on the Matching string
func (g *GroupRuleService) Add(groupRuleName string, groupRuleCondition string) (*GroupRule, *Response, error) {

	if groupRuleName == "" {
		return nil, nil, errors.New("groupRuleName parameter is required for ADD")
	}
	if groupRuleCondition == "" {
		return nil, nil, errors.New("groupRuleCondition parameter is required for ADD")
	}
	newGroupRule := newGroupRule{}
	newGroupRule.Name = groupRuleName
	newGroupRule.Conditions.Expression.Value = groupRuleCondition
	newGroupRule.Conditions.Expression.Type = groupRuleExpressionType

	u := fmt.Sprintf("groups/rules")

	req, err := g.client.NewRequest("POST", u, newGroupRule)

	if err != nil {
		return nil, nil, err
	}

	grouprule := new(GroupRule)

	resp, err := g.client.Do(req, grouprule)

	if err != nil {
		return nil, resp, err
	}

	return grouprule, resp, err
}
