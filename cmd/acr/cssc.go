// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package main

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/Azure/acr-cli/cmd/api"
	v1 "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"

	"oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/registry/remote"
	"oras.land/oras-go/v2/registry/remote/auth"
	"oras.land/oras-go/v2/registry/remote/retry"
)

const (
	newCsscCmdLongMessage       = `acr cssc: Manage cssc configurations for the registry.`
	newCsscFilterCmdLongMessage = `acr cssc filter: Manage cssc patch filters for the registry.`
	newFilterListCmdLongMessage = `acr cssc filter list: List cssc filters for the registry.`
	defaultFilterRepoName       = "continuouspatchingfilters"
	defaultFilterJsonFileName   = `filters.json`
)

// Besides the registry name and authentication information only the repository is needed.
type csscParameters struct {
	*rootParameters
}

type FilterContent struct {
	Repository string   `json:"repository"`
	Tags       []string `json:"tags"`
}

type FilteredRepository struct {
	Repository string
	Tag        string
}

func newCsscCmd(rootParams *rootParameters) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "cssc",
		Short: "Manage cssc configurations for a registry",
		Long:  newCsscCmdLongMessage,
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.Help()
			return nil
		},
	}

	newCsscFilterCmd := newCsscPatchFilterCmd(rootParams)

	cmd.AddCommand(
		newCsscFilterCmd,
	)

	return cmd
}

func newCsscPatchFilterCmd(rootParams *rootParameters) *cobra.Command {
	csscParams := csscParameters{rootParameters: rootParams}
	cmd := &cobra.Command{
		Use:   "filter",
		Short: "Manage cssc continuous patch filters for a registry",
		Long:  newCsscFilterCmdLongMessage,
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.Help()
			return nil
		},
	}

	filterListCmd := newPatchFilterListCmd(&csscParams)

	cmd.AddCommand(
		filterListCmd,
	)

	return cmd
}

// The tag command can be used to either list tags or delete tags inside a repository.
// that can be done with the tag list and tag delete commands respectively.
func newPatchFilterListCmd(csscParams *csscParameters) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List cssc continuous patch filters for a registry",
		Long:  newFilterListCmdLongMessage,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()
			registryName, err := csscParams.GetRegistryName()
			loginURL := api.LoginURL(registryName)
			var filter []FilterContent
			acrClient, err := api.GetAcrCLIClientWithAuth(loginURL, csscParams.username, csscParams.password, csscParams.configs)
			if err != nil {
				return err
			}

			// 0. Connect to the remote repository
			repo, err := remote.NewRepository(fmt.Sprintf("%s/%s", loginURL, defaultFilterRepoName))
			if err != nil {
				fmt.Println("106")
				panic(err)
			}

			repo.Client = &auth.Client{
				Client: retry.DefaultClient,
				Cache:  auth.DefaultCache,
				Credential: auth.StaticCredential(loginURL, auth.Credential{
					Username: csscParams.username,
					Password: csscParams.password,
				}),
			}

			// 1. Get manifest by tag
			tag := "latest"
			descriptor, err := repo.Resolve(ctx, tag)
			if err != nil {
				panic(err)
			}
			rc, err := repo.Fetch(ctx, descriptor)
			if err != nil {
				panic(err)
			}
			defer rc.Close() // don't forget to close
			pulledManifestContent, err := content.ReadAll(rc, descriptor)
			if err != nil {
				panic(err)
			}
			//fmt.Println(string(pulledManifestContent))

			// 2. Parse the pulled manifest and fetch its layers.
			var pulledManifest v1.Manifest
			if err := json.Unmarshal(pulledManifestContent, &pulledManifest); err != nil {
				panic(err)
			}

			fileContent := []byte{}
			for _, layer := range pulledManifest.Layers {
				fileContent, err = content.FetchAll(ctx, repo, layer)
				if err != nil {
					panic(err)
				}
				//fmt.Println(string(fileContent))
			}

			//3. Unmarshal the JSON file data into the filter slice
			if err := json.Unmarshal(fileContent, &filter); err != nil {
				fmt.Printf("Error unmarshalling JSON data: %v", err)
			}

			//4. Get a list of filtered repository and tag which matches the filter
			filteredResult, err := listAndFilterRepositories(ctx, acrClient, loginURL, filter)

			//5. Print the list of filtered repository and tag
			for _, result := range filteredResult {
				fmt.Printf("%s/%s:%s\n", loginURL, result.Repository, result.Tag)
			}

			return nil
		},
	}

	return cmd
}

// listAndFilterRepositories returns a list of repositories and tags that match the filter
func listAndFilterRepositories(ctx context.Context, acrClient api.AcrCLIClientInterface, loginURL string, filterRepositories []FilterContent) ([]FilteredRepository, error) {

	// Get all repositories
	allRepos, err := acrClient.GetAcrRepositories(ctx, "", nil)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get repositories for a registry")
	}

	// Initialize the result slice
	var resultRepos []FilteredRepository = nil

	// Loop through all the repositories
	if allRepos != nil {
		allRepositories := *allRepos.Names

		for _, filterRepository := range filterRepositories {
			for _, repository := range allRepositories {
				if repository == filterRepository.Repository {
					// Get all tags for the repository if the repository is present in the filter
					repositoryTags, err := returnTags(ctx, acrClient, loginURL, repository)
					if err != nil {
						return nil, err
					}
					if filterRepository.Tags != nil {
						for _, filterRepositoryTag := range filterRepository.Tags {
							for _, repositoryTag := range repositoryTags {
								if filterRepositoryTag == *repositoryTag.Name {
									var repo = FilteredRepository{Repository: filterRepository.Repository, Tag: filterRepositoryTag}
									resultRepos = appendIfNotPresent(resultRepos, repo)
								}
							}
						}
					}
				}
			}

			if err != nil {
				return nil, err
			}
		}
	}
	return resultRepos, err
}

func appendIfNotPresent(slice []FilteredRepository, element FilteredRepository) []FilteredRepository {
	for _, existing := range slice {
		if existing == element {
			return slice // Element already exists, return the original slice
		}
	}
	// Element is not present, append it to the slice
	return append(slice, element)
}
