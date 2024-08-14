package common

import (
	"context"
	"net/http"
	"time"

	"github.com/Azure/acr-cli/acr"
	"github.com/Azure/go-autorest/autorest"
)

var (
	TestCtx      = context.Background()
	TestLoginURL = "foo.azurecr.io"
	TestRepo     = "bar"

	TagName             = "latest"
	TagName1            = "v1"
	TagName2            = "v2"
	TagName3            = "v3"
	TagName4            = "v4"
	TagName1FloatingTag = "v1-patched"
	TagName2FloatingTag = "v2-patched"
	TagName1Semver1     = "v1-1"
	TagName2Semver1     = "v2-1"
	TagName3Semver1     = "v3-1"
	TagName4Semver1     = "v4-1"
	TagName1Semver2     = "v1-2"
	TagName2Semver2     = "v2-2"
	TagName3Semver2     = "v3-2"
	TagName4Semver2     = "v4-2"
	RepoName1           = "repo1"
	RepoName2           = "repo2"
	RepoName3           = "repo3"
	RepoName4           = "repo4"
	deleteEnabled       = true
	lastUpdateTime      = time.Now().Add(-15 * time.Minute).UTC().Format(time.RFC3339Nano)
	writeEnabled        = true
	digest              = "sha256:2830cc0fcddc1bc2bd4aeab0ed5ee7087dab29a49e65151c77553e46a7ed5283" //#nosec G101
	multiArchDigest     = "sha256:d88fb54ba4424dada7c928c6af332ed1c49065ad85eafefb6f26664695015119" //#nosec G101

	NotFoundResponse = autorest.Response{
		Response: &http.Response{
			StatusCode: 404,
		},
	}
	DeletedResponse = autorest.Response{
		Response: &http.Response{
			StatusCode: 200,
		},
	}

	// Response for the GetAcrTags when the repository is not found.
	NotFoundTagResponse = &acr.RepositoryTagsType{
		Response: NotFoundResponse,
	}

	// Response for the GetAcrTags when there are no tags on the testRepo.
	EmptyListTagsResult = &acr.RepositoryTagsType{
		Registry:       &TestLoginURL,
		ImageName:      &TestRepo,
		TagsAttributes: nil,
	}

	// Response for the GetAcrTags when there is one tag on the testRepo.
	OneTagResult = &acr.RepositoryTagsType{
		Response: autorest.Response{
			Response: &http.Response{
				StatusCode: 200,
			},
		},
		Registry:  &TestLoginURL,
		ImageName: &TestRepo,
		TagsAttributes: &[]acr.TagAttributesBase{
			{
				Name:                 &TagName,
				LastUpdateTime:       &lastUpdateTime,
				ChangeableAttributes: &acr.ChangeableAttributes{DeleteEnabled: &deleteEnabled, WriteEnabled: &writeEnabled},
				Digest:               &digest,
			},
		},
	}

	FourTagsResult = &acr.RepositoryTagsType{
		Response: autorest.Response{
			Response: &http.Response{
				StatusCode: 200,
			},
		},
		Registry:  &TestLoginURL,
		ImageName: &TestRepo,
		TagsAttributes: &[]acr.TagAttributesBase{{
			Name:                 &TagName1,
			LastUpdateTime:       &lastUpdateTime,
			ChangeableAttributes: &acr.ChangeableAttributes{DeleteEnabled: &deleteEnabled, WriteEnabled: &writeEnabled},
			Digest:               &digest,
		}, {
			Name:                 &TagName2,
			LastUpdateTime:       &lastUpdateTime,
			ChangeableAttributes: &acr.ChangeableAttributes{DeleteEnabled: &deleteEnabled, WriteEnabled: &writeEnabled},
			Digest:               &digest,
		}, {
			Name:                 &TagName3,
			LastUpdateTime:       &lastUpdateTime,
			ChangeableAttributes: &acr.ChangeableAttributes{DeleteEnabled: &deleteEnabled, WriteEnabled: &writeEnabled},
			Digest:               &multiArchDigest,
		}, {
			Name:                 &TagName4,
			LastUpdateTime:       &lastUpdateTime,
			ChangeableAttributes: &acr.ChangeableAttributes{DeleteEnabled: &deleteEnabled, WriteEnabled: &writeEnabled},
			Digest:               &digest,
		}},
	}

	EightTagResultWithPatchTags = &acr.RepositoryTagsType{
		Response: autorest.Response{
			Response: &http.Response{
				StatusCode: 200,
			},
		},
		Registry:  &TestLoginURL,
		ImageName: &TestRepo,
		TagsAttributes: &[]acr.TagAttributesBase{{
			Name:                 &TagName1,
			LastUpdateTime:       &lastUpdateTime,
			ChangeableAttributes: &acr.ChangeableAttributes{DeleteEnabled: &deleteEnabled, WriteEnabled: &writeEnabled},
			Digest:               &digest,
		}, {
			Name:                 &TagName1Semver1,
			LastUpdateTime:       &lastUpdateTime,
			ChangeableAttributes: &acr.ChangeableAttributes{DeleteEnabled: &deleteEnabled, WriteEnabled: &writeEnabled},
			Digest:               &digest,
		}, {
			Name:                 &TagName1Semver2,
			LastUpdateTime:       &lastUpdateTime,
			ChangeableAttributes: &acr.ChangeableAttributes{DeleteEnabled: &deleteEnabled, WriteEnabled: &writeEnabled},
			Digest:               &digest,
		}, {
			Name:                 &TagName1FloatingTag,
			LastUpdateTime:       &lastUpdateTime,
			ChangeableAttributes: &acr.ChangeableAttributes{DeleteEnabled: &deleteEnabled, WriteEnabled: &writeEnabled},
			Digest:               &digest,
		}, {
			Name:                 &TagName2,
			LastUpdateTime:       &lastUpdateTime,
			ChangeableAttributes: &acr.ChangeableAttributes{DeleteEnabled: &deleteEnabled, WriteEnabled: &writeEnabled},
			Digest:               &digest,
		}, {
			Name:                 &TagName2Semver1,
			LastUpdateTime:       &lastUpdateTime,
			ChangeableAttributes: &acr.ChangeableAttributes{DeleteEnabled: &deleteEnabled, WriteEnabled: &writeEnabled},
			Digest:               &digest,
		}, {
			Name:                 &TagName2Semver2,
			LastUpdateTime:       &lastUpdateTime,
			ChangeableAttributes: &acr.ChangeableAttributes{DeleteEnabled: &deleteEnabled, WriteEnabled: &writeEnabled},
			Digest:               &digest,
		}, {
			Name:                 &TagName2FloatingTag,
			LastUpdateTime:       &lastUpdateTime,
			ChangeableAttributes: &acr.ChangeableAttributes{DeleteEnabled: &deleteEnabled, WriteEnabled: &writeEnabled},
			Digest:               &digest,
		}},
	}
)
