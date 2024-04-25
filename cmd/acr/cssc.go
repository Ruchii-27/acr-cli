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
	copPatchCmdLongMessage    = `acr copa: patches all images in registry.`
	defaultFilterRepoName     = "continuouspatchingfilters"
	defaultFilterJsonFileName = `filters.json`
)

// Besides the registry name and authentication information only the repository is needed.
type copaParameters struct {
	*rootParameters
	repoName string
}

type FilterContent struct {
	Repository string   `json:"repository"`
	Tags       []string `json:"tags"`
}

type FilteredRepository struct {
	Repository string
	Tag        string
}

// The tag command can be used to either list tags or delete tags inside a repository.
// that can be done with the tag list and tag delete commands respectively.
func newCopaPatchCmd(rootParams *rootParameters) *cobra.Command {
	copaParams := copaParameters{rootParameters: rootParams}
	cmd := &cobra.Command{
		Use:   "cssc",
		Short: "Patches repo inside a registry",
		Long:  copPatchCmdLongMessage,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()
			registryName, err := copaParams.GetRegistryName()
			loginURL := api.LoginURL(registryName)
			var filter []FilterContent
			acrClient, err := api.GetAcrCLIClientWithAuth(loginURL, copaParams.username, copaParams.password, copaParams.configs)
			if err != nil {
				return err
			}

			// 0. Connect to the remote repository
			repo, err := remote.NewRepository(registryName + "/" + copaParams.repoName)
			if err != nil {
				panic(err)
			}

			repo.Client = &auth.Client{
				Client: retry.DefaultClient,
				Cache:  auth.DefaultCache,
				Credential: auth.StaticCredential(registryName, auth.Credential{
					Username: copaParams.username,
					Password: copaParams.password,
				}),
			}

			// 1. Fetch the artifact manifest by tag.
			tag := "latest"
			desc, err := repo.Manifests().Resolve(ctx, tag)
			if err != nil {
				panic(err)
			}
			//fmt.Println("digest", desc.Digest.String())

			// 2. Use the digest to fetch the artifact manifest.
			descriptor, rc, err := repo.FetchReference(ctx, desc.Digest.String())
			if err != nil {
				panic(err)
			}
			defer rc.Close()

			pulledContent, err := content.ReadAll(rc, descriptor)
			if err != nil {
				panic(err)
			}
			//fmt.Println("Pulled content from the registry: ", string(pulledContent))

			// 3. Parse the pulled artifact manifest and fetch its layers.
			var pulledManifest v1.Manifest
			if err := json.Unmarshal(pulledContent, &pulledManifest); err != nil {
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

			//4. Unmarshal the JSON file data into the filter slice
			if err := json.Unmarshal(fileContent, &filter); err != nil {
				fmt.Printf("Error unmarshalling JSON data: %v", err)
			}

			//5. Get a list of filtered repository and tag which matches the filter
			filteredResult, err := listAndFilterRepositories(ctx, acrClient, loginURL, filter)

			//6. Print the list of filtered repository and tag
			for _, result := range filteredResult {
				fmt.Printf("%s/%s:%s\n", loginURL, result.Repository, result.Tag)
			}

			return nil
		},
	}

	cmd.PersistentFlags().StringVar(&copaParams.repoName, "repository", "", "The repository name where the filter file exists.")
	cmd.MarkPersistentFlagRequired("repository")

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
