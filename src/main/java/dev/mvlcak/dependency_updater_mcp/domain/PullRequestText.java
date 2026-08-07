package dev.mvlcak.dependency_updater_mcp.domain;

/**
 * What the LLM is allowed to decide about the pull request: the prose, and nothing else.
 *
 * Same split as {@link UpgradeChoice}. Versions, coordinates and CVE ids are appended to
 * the body by code afterwards, from the blackboard, so a reviewer reading "closes
 * CVE-2022-42003" is reading a fact rather than something the model remembered.
 */
public record PullRequestText(String title, String body) {}
