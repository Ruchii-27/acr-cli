// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	orasauth "github.com/Azure/acr-cli/auth/oras"
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
	newCsscCmdLongMessage        = `acr cssc: Lists cssc configurations for the registry. Use the subcommands to list continuous patch filters for the registry.`
	newPatchFilterCmdLongMessage = `acr cssc patch: List cssc continuous patch filters for a registry. Use the --filter-policy flag to specify the repo where filters exists. Example: acr cssc patch --filter-policy continuouspatchpolicy:v1.`
)

// Besides the registry name and authentication information only the repository is needed.
type csscParameters struct {
	*rootParameters
	filterPolicy  string
	showPatchTags bool
}

type FilterContent struct {
	Repository string   `json:"repository"`
	Tags       []string `json:"tags"`
}

type FilteredRepository struct {
	Repository string
	Tag        string
	PatchTag   string
}

// The cssc command can be used to list cssc configurations for a registry.
func newCsscCmd(rootParams *rootParameters) *cobra.Command {
	csscParams := csscParameters{rootParameters: rootParams}
	cmd := &cobra.Command{
		Use:   "cssc",
		Short: "Lists cssc configurations for a registry",
		Long:  newCsscCmdLongMessage,
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.Help()
			return nil
		},
	}

	newCsscPatchFilterCmd := newPatchFilterCmd(&csscParams)

	cmd.AddCommand(
		newCsscPatchFilterCmd,
	)

	return cmd
}

// The patch subcommand can be used to list cssc continuous patch filters for a registry or to list matching tags and its corresponding patch tag if present.
func newPatchFilterCmd(csscParams *csscParameters) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "patch",
		Short: "Manage cssc patch operations for a registry",
		Long:  newPatchFilterCmdLongMessage,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()
			registryName, err := csscParams.GetRegistryName()
			if err != nil {
				return err
			}
			loginURL := api.LoginURL(registryName)
			acrClient, err := api.GetAcrCLIClientWithAuth(loginURL, csscParams.username, csscParams.password, csscParams.configs)
			if err != nil {
				return err
			}

			// if patch is called with filter-policy flag, get the filter policy from the specified repository and list the repositories and tags that match the filter
			if csscParams.filterPolicy != "" {
				return listFilteredRepositoriesByFilterPolicy(ctx, csscParams, loginURL, acrClient)
			}

			return nil
		},
	}

	cmd.PersistentFlags().StringVar(&csscParams.filterPolicy, "filter-policy", "", "The filter policy defined by the filter.json uploaded in a repo:tag. For v1, it will be continuouspatchpolicy:v1")
	cmd.Flags().BoolVar(&csscParams.showPatchTags, "show-patch-tags", false, "Use this flag in combination with --filter-policy to get patched image tag (if it exists) for repositories and tags that match the filter. Example: acr cssc patch --filter-policy continuouspatchpolicy:v1 --show-patch-tags")

	return cmd
}

// Lists all repositories and tags that match the filter defined by a json file uploaded in a repository for a registry
func listFilteredRepositoriesByFilterPolicy(ctx context.Context, csscParams *csscParameters, loginURL string, acrClient api.AcrCLIClientInterface) error {

	var filter []FilterContent = nil

	// 0. Get the repository and tag from the filter policy
	repoTag := strings.Split(csscParams.filterPolicy, ":")
	filterRepoName := repoTag[0]
	filterRepoTagName := repoTag[1]

	// 1. Connect to the remote repository
	repo, err := remote.NewRepository(fmt.Sprintf("%s/%s", loginURL, filterRepoName))
	if err != nil {
		panic(err)
	}

	getRegistryCredsFromStore(csscParams, loginURL)

	repo.Client = &auth.Client{
		Client: retry.DefaultClient,
		Cache:  auth.NewCache(),
		Credential: auth.StaticCredential(loginURL, auth.Credential{
			Username: csscParams.username,
			Password: csscParams.password,
		}),
	}
	// 2. Get manifest by tag
	descriptor, err := repo.Resolve(ctx, filterRepoTagName)
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

	// 3. Parse the pulled manifest and fetch its layers.
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

	//4. Unmarshal the JSON file data into the filter slice
	if err := json.Unmarshal(fileContent, &filter); err != nil {
		fmt.Printf("Error unmarshalling JSON data: %v ", err)
	}

	//5. Get a list of filtered repository and tag which matches the filter
	filteredResult, err := getAndFilterRepositories(ctx, acrClient, loginURL, filter)
	if err != nil {
		return err
	}

	//6. Print the list of filtered repository and tag
	if len(filteredResult) == 0 {
		fmt.Println("No matching repository and tag found")
		return nil
	}

	if csscParams.showPatchTags {
		fmt.Println("Listing repositories and tags matching the filter with corrosponding patch tag (if present):")
		for _, result := range filteredResult {
			fmt.Printf("%s/%s:%s,%s\n", loginURL, result.Repository, result.Tag, result.PatchTag)
		}
	} else {
		fmt.Println("Listing repositories and tags matching the filter:")
		for _, result := range filteredResult {
			fmt.Printf("%s/%s:%s\n", loginURL, result.Repository, result.Tag)
		}
	}

	return nil
}

// Gets all repositories and tags and filters the repositories and tags based on the filter
func getAndFilterRepositories(ctx context.Context, acrClient api.AcrCLIClientInterface, loginURL string, filterRepositories []FilterContent) ([]FilteredRepository, error) {

	// Get all repositories
	allRepos, err := acrClient.GetAcrRepositories(ctx, "", nil)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get repositories for a registry")
	}

	// Initialize the result slice
	var resultRepos []FilteredRepository = nil

	// Loop through all the repositories and tags and filter the repositories and tags based on the filter
	if allRepos != nil {
		allRepositories := *allRepos.Names
		for _, filterRepository := range filterRepositories {
			for _, repository := range allRepositories {
				if repository == filterRepository.Repository {
					// Get all tags for the repository if the repository is present in the filter
					repositoryTags, err := listTags(ctx, acrClient, loginURL, repository)
					if err != nil {
						return nil, err
					}

					for _, repositoryTag := range repositoryTags {
						if filterRepository.Tags == nil || len(filterRepository.Tags) == 0 { // If no tags are specified in the filter for the repository, then add all tags
							if strings.Contains(*repositoryTag.Name, "-patched") {
								originalTag := strings.Split(*repositoryTag.Name, "-patched")[0]
								repo := FilteredRepository{Repository: filterRepository.Repository, Tag: originalTag, PatchTag: *repositoryTag.Name}
								resultRepos = appendElement(resultRepos, repo)
							} else {
								repo := FilteredRepository{Repository: filterRepository.Repository, Tag: *repositoryTag.Name, PatchTag: *repositoryTag.Name}
								resultRepos = appendElement(resultRepos, repo)
							}
						} else { // If tags are specified in the filter for the repository, then add only the tags that match the filter
							for _, filterRepositoryTag := range filterRepository.Tags {
								if *repositoryTag.Name == filterRepositoryTag {
									repo := FilteredRepository{Repository: filterRepository.Repository, Tag: *repositoryTag.Name, PatchTag: *repositoryTag.Name}
									resultRepos = appendElement(resultRepos, repo)
								}
								if *repositoryTag.Name == filterRepositoryTag+"-patched" {
									repo := FilteredRepository{Repository: filterRepository.Repository, Tag: filterRepositoryTag, PatchTag: filterRepositoryTag + "-patched"}
									resultRepos = appendElement(resultRepos, repo)
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

func getRegistryCredsFromStore(csscParams *csscParameters, loginURL string) {
	// If both username and password are empty then the docker config file will be used, it can be found in the default
	// location or in a location specified by the configs string array
	if csscParams.username == "" || csscParams.password == "" {
		store, err := orasauth.NewStore(csscParams.configs...)
		if err != nil {
			errors.Wrap(err, "error resolving authentication")
		}
		cred, err := store.Credential(context.Background(), loginURL)
		if err != nil {
			errors.Wrap(err, "error resolving authentication")
		}
		csscParams.username = cred.Username
		csscParams.password = cred.Password

		// fallback to refresh token if it is available
		if csscParams.password == "" && cred.RefreshToken != "" {
			csscParams.password = cred.RefreshToken
		}
	}
}

func appendElement(slice []FilteredRepository, element FilteredRepository) []FilteredRepository {
	for _, existing := range slice {
		if existing.Repository == element.Repository && existing.Tag == element.Tag {
			// Remove the existing element from the slice
			for i, v := range slice {
				if v.Repository == element.Repository && v.Tag == element.Tag {
					slice = append(slice[:i], slice[i+1:]...)
					break
				}
			}
		}
	}
	//Append element to the slice
	return append(slice, element)
}
