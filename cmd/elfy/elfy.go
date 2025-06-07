package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/xplshn/elfy"

	"github.com/urfave/cli/v3"
)

func main() {
	app := &cli.Command{
		Name:  "elfy",
		Usage: "Tool to manipulate ELF sections",
		Commands: []*cli.Command{
			{
				Name:      "list-sections",
				Usage:     "List all sections in the ELF file",
				Action:    listSections,
				ArgsUsage: "<input_elf_file>",
			},
			{
				Name:  "read-section",
				Usage: "Read and print the content of a section",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:     "name",
						Usage:    "Name of the section to read",
						Required: true,
					},
				},
				Action:    readSection,
				ArgsUsage: "<input_elf_file>",
			},
			{
				Name:  "add-section",
				Usage: "Add or replace a section with content from a file",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:     "name",
						Usage:    "Name of the section",
						Required: true,
					},
					&cli.StringFlag{
						Name:     "file",
						Usage:    "File containing the section data",
						Required: true,
					},
					&cli.StringFlag{
						Name:  "output",
						Usage: "Output ELF file",
						Value: "",
					},
				},
				Action:    addSectionFromFile,
				ArgsUsage: "<input_elf_file>",
			},
			{
				Name:  "add-section-string",
				Usage: "Add or replace a section with a string content",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:     "name",
						Usage:    "Name of the section",
						Required: true,
					},
					&cli.StringFlag{
						Name:     "content",
						Usage:    "String content for the section",
						Required: true,
					},
					&cli.StringFlag{
						Name:  "output",
						Usage: "Output ELF file",
						Value: "",
					},
				},
				Action:    addSectionFromString,
				ArgsUsage: "<input_elf_file>",
			},
			{
				Name:  "remove-section",
				Usage: "Remove a section",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:     "name",
						Usage:    "Name of the section to remove",
						Required: true,
					},
					&cli.StringFlag{
						Name:  "output",
						Usage: "Output ELF file",
						Value: "",
					},
				},
				Action:    removeSection,
				ArgsUsage: "<input_elf_file>",
			},
		},
	}

	err := app.Run(context.Background(), os.Args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func listSections(ctx context.Context, c *cli.Command) error {
	if c.NArg() != 1 {
		return fmt.Errorf("missing input ELF file")
	}
	inputFile := c.Args().First()
	elfData, err := os.ReadFile(inputFile)
	if err != nil {
		return fmt.Errorf("error reading file: %v", err)
	}
	sections, err := elfy.ListSections(elfData)
	if err != nil {
		return err
	}
	for _, sec := range sections {
		fmt.Println(sec)
	}
	return nil
}

func readSection(ctx context.Context, c *cli.Command) error {
	if c.NArg() != 1 {
		return fmt.Errorf("missing input ELF file")
	}
	inputFile := c.Args().First()
	sectionName := c.String("name")
	elfData, err := os.ReadFile(inputFile)
	if err != nil {
		return fmt.Errorf("error reading file: %v", err)
	}
	data, err := elfy.ReadSection(elfData, sectionName)
	if err != nil {
		return err
	}
	fmt.Printf("Content of section %s:\n%s\n", sectionName, string(data))
	return nil
}

func addSectionFromFile(ctx context.Context, c *cli.Command) error {
	if c.NArg() != 1 {
		return fmt.Errorf("missing input ELF file")
	}
	inputFile := c.Args().First()
	sectionName := c.String("name")
	filePath := c.String("file")
	outputFile := c.String("output")
	if outputFile == "" {
		outputFile = filepath.Base(inputFile) + ".modified"
	}
	sectionData, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("error reading section data file: %v", err)
	}
	elfData, err := os.ReadFile(inputFile)
	if err != nil {
		return fmt.Errorf("error reading ELF file: %v", err)
	}
	newElfData, err := elfy.AddOrReplaceSection(elfData, sectionName, sectionData)
	if err != nil {
		return fmt.Errorf("error adding or replacing section: %v", err)
	}
	err = os.WriteFile(outputFile, newElfData, 0644)
	if err != nil {
		return fmt.Errorf("error writing output file: %v", err)
	}
	fmt.Printf("Section %s added or replaced in %s\n", sectionName, outputFile)
	return nil
}

func addSectionFromString(ctx context.Context, c *cli.Command) error {
	if c.NArg() != 1 {
		return fmt.Errorf("missing input ELF file")
	}
	inputFile := c.Args().First()
	sectionName := c.String("name")
	content := c.String("content")
	outputFile := c.String("output")
	if outputFile == "" {
		outputFile = filepath.Base(inputFile) + ".modified"
	}
	sectionData := []byte(content)
	elfData, err := os.ReadFile(inputFile)
	if err != nil {
		return fmt.Errorf("error reading ELF file: %v", err)
	}
	newElfData, err := elfy.AddOrReplaceSection(elfData, sectionName, sectionData)
	if err != nil {
		return fmt.Errorf("error adding or replacing section: %v", err)
	}
	err = os.WriteFile(outputFile, newElfData, 0644)
	if err != nil {
		return fmt.Errorf("error writing output file: %v", err)
	}
	fmt.Printf("Section %s added or replaced in %s\n", sectionName, outputFile)
	return nil
}

func removeSection(ctx context.Context, c *cli.Command) error {
	if c.NArg() != 1 {
		return fmt.Errorf("missing input ELF file")
	}
	inputFile := c.Args().First()
	sectionName := c.String("name")
	outputFile := c.String("output")
	if outputFile == "" {
		outputFile = filepath.Base(inputFile) + ".modified"
	}
	elfData, err := os.ReadFile(inputFile)
	if err != nil {
		return fmt.Errorf("error reading ELF file: %v", err)
	}
	newElfData, err := elfy.RemoveSection(elfData, sectionName)
	if err != nil {
		return fmt.Errorf("error removing section: %v", err)
	}
	err = os.WriteFile(outputFile, newElfData, 0644)
	if err != nil {
		return fmt.Errorf("error writing output file: %v", err)
	}
	fmt.Printf("Section %s removed from %s\n", sectionName, outputFile)
	return nil
}
