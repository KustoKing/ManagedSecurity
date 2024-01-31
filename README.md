# Managed Cyber Security

This project is meant to manage and deploy cyber security environemnts. The first feature is to manage and deploy Microsoft Sentinel

## Folder Structure

This project contains the following folder structure

### Pipelines

This folder contains Azure DevOps pipelines

### Scripts

This Folder contains scripts for the heavy lifting.

### Tenants 

The contain all the tenants in a folder with a name in the form of a string. The folder contains a tenantname.config.json file with all the required parameters.

## Prerequisites

The initial intention of this script is to deploy everything from an Azure DevOps environment. So the basics are a Azure DevOps organization, a repository wich holds all files, parallel jobs to execute the scripts, a service connection to connect to the Azure Resource Manager