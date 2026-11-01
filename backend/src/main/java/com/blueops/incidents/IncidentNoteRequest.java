package com.blueops.incidents;

import jakarta.validation.constraints.NotBlank;

public class IncidentNoteRequest {

    @NotBlank(message = "Note content cannot be empty")
    private String noteText;

    public IncidentNoteRequest() {}

    public IncidentNoteRequest(String noteText) {
        this.noteText = noteText;
    }

    public String getNoteText() { return noteText; }
    public void setNoteText(String noteText) { this.noteText = noteText; }
}
