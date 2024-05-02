// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Azure/acr-cli/auth/oras"
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
	filterPolicy string
	image        string
	internal     bool
}

type FilterContent struct {
	Repository string   `json:"repository"`
	Tags       []string `json:"tags"`
}

type FilteredRepository struct {
	Repository string
	Tag        string
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
			getRegistryCredsFromStore(csscParams, loginURL)
			acrClient, err := api.GetAcrCLIClientWithAuth(loginURL, csscParams.username, csscParams.password, csscParams.configs)
			if err != nil {
				return err
			}

			// if patch is called with filter-policy flag, get the filter policy from the repository and list the repositories and tags that match the filter
			if csscParams.filterPolicy != "" {
				return listFilteredRepositoriesByFilterPolicy(ctx, csscParams, loginURL, acrClient)
			}

			// if patch is called with image flag, get the tags for the repository and fetch the matching tag and its corresponding patch tag if present
			if csscParams.image != "" {
				return listMatchingAndPatchTags(ctx, csscParams, loginURL, acrClient)
			}

			return nil
		},
	}

	cmd.PersistentFlags().StringVar(&csscParams.filterPolicy, "filter-policy", "", "The filter policy defined by the filter.json uploaded in a repo:tag. For v1, it will be continuouspatchpolicy:v1")
	cmd.Flags().BoolVar(&csscParams.internal, "internal", false, "Use this flag in combination with --filter-policy flag to replace original tag with patched tag (if it exists) in the list of repositories and tags that match the filter. Example: acr cssc patch --filter-policy continuouspatchpolicy:v1 --internal")
	cmd.PersistentFlags().StringVar(&csscParams.image, "image", "", "The image in the format loginUrl/repo:tag to fetch the matching tag and its corresponding patch tag if present. Example: acr cssc patch --image loginUrl/repo:tag")

	return cmd
}

// Lists all repositories and tags that match the filter defined by a json file uploaded in a repository for a registry
func listFilteredRepositoriesByFilterPolicy(ctx context.Context, csscParams *csscParameters, loginURL string, acrClient *api.AcrCLIClient) error {

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
	repo.Client = &auth.Client{
		Client: retry.DefaultClient,
		Cache:  auth.DefaultCache,
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
		fmt.Printf("Error unmarshalling JSON data: %v", err)
	}

	//5. Get a list of filtered repository and tag which matches the filter
	isInternal := csscParams.internal
	filteredResult, err := getAndFilterRepositories(ctx, acrClient, loginURL, isInternal, filter)
	if err != nil {
		return err
	}

	//6. Print the list of filtered repository and tag
	for _, result := range filteredResult {
		fmt.Printf("%s/%s:%s\n", loginURL, result.Repository, result.Tag)
	}
	return nil
}

// Lists the matching tag and its corresponding patch tag if present for a given image in the format loginUrl/repo:tag
func listMatchingAndPatchTags(ctx context.Context, csscParams *csscParameters, loginURL string, acrClient *api.AcrCLIClient) error {

	// if image is not in the format loginurl/repo:tag, return error
	if !strings.Contains(csscParams.image, "/") || !strings.Contains(csscParams.image, ":") {
		return errors.New("Invalid image filter format. Please provide the image in the format loginurl/repo:tag")
	}

	// if loginurl from image dose not match with LoginURL, return error
	if !strings.Contains(csscParams.image, loginURL) {
		return errors.New("Invalid image filter. Please provide the loginurl that matches the registry name")
	}

	// split csscParams.image by / and : to get the repository and tag
	repository, tag := "", ""
	if arr := strings.Split(csscParams.image, "/"); len(arr) > 1 {
		if arr1 := strings.Split(arr[1], ":"); len(arr1) > 1 {
			repository, tag = arr1[0], arr1[1]
		}
	}

	repositoryTags, err := returnTags(ctx, acrClient, loginURL, repository)
	if err != nil {
		panic(err)
	}

	matchingTag := ""
	patchTag := ""
	for _, repositoryTag := range repositoryTags {
		if *repositoryTag.Name == tag {
			matchingTag = *repositoryTag.Name
		}
		if *repositoryTag.Name == tag+"-patched" {
			patchTag = *repositoryTag.Name
		}
	}

	if matchingTag == "" && patchTag == "" {
		err = errors.New("No matching tag found")
	} else if matchingTag != "" && patchTag != "" {
		fmt.Printf("%s->%s,%s\n", repository, matchingTag, patchTag)
	} else if patchTag == "" && matchingTag != "" {
		fmt.Printf("%s->%s,%s\n", repository, matchingTag, matchingTag)
	}

	return nil
}

// Gets all repositories and tags and filters the repositories and tags based on the filter
func getAndFilterRepositories(ctx context.Context, acrClient api.AcrCLIClientInterface, loginURL string, isInternal bool, filterRepositories []FilterContent) ([]FilteredRepository, error) {

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
					repositoryTags, err := returnTags(ctx, acrClient, loginURL, repository)
					if err != nil {
						return nil, err
					}
					if isInternal {
						if filterRepository.Tags != nil {
							for _, filterRepositoryTag := range filterRepository.Tags {
								for _, repositoryTag := range repositoryTags {
									if *repositoryTag.Name == filterRepositoryTag || *repositoryTag.Name == filterRepositoryTag+"-patched" {
										var repo = FilteredRepository{Repository: filterRepository.Repository, Tag: *repositoryTag.Name}
										resultRepos = replaceOriginalWithPatchedIfPresent(resultRepos, repo)
									}
								}
							}
						}
					} else {
						if filterRepository.Tags != nil {
							for _, filterRepositoryTag := range filterRepository.Tags {
								for _, repositoryTag := range repositoryTags {
									if *repositoryTag.Name == filterRepositoryTag {
										var repo = FilteredRepository{Repository: filterRepository.Repository, Tag: *repositoryTag.Name}
										resultRepos = appendIfNotPresent(resultRepos, repo)
									}
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
	if csscParams.username == "" || csscParams.password == "" {
		store, err := oras.NewStore(csscParams.configs...)
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

func appendIfNotPresent(slice []FilteredRepository, element FilteredRepository) []FilteredRepository {
	for _, existing := range slice {
		if existing == element {
			return slice // Element already exists, return the original slice
		}
	}
	// Element is not present, append it to the slice
	return append(slice, element)
}

func replaceOriginalWithPatchedIfPresent(slice []FilteredRepository, element FilteredRepository) []FilteredRepository {
	for _, current := range slice {
		if current.Repository == element.Repository {
			if current.Tag == element.Tag {
				return slice // Element already exists, return the original slice
			}

			if element.Tag == current.Tag+"-patched" {
				// remove from slice the original tag if patched tag is found
				for i, v := range slice {
					if v.Repository == current.Repository && v.Tag == current.Tag {
						slice = append(slice[:i], slice[i+1:]...)
						break
					}
				}
				// add the new element to the slice
				slice = append(slice, element)
				return slice
			}
		}
	}
	slice = append(slice, element)
	return slice
}
