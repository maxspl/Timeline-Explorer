require([
    'splunkjs/mvc/tableview',
    'splunkjs/mvc/eventsviewerview',
    'splunkjs/mvc/searchmanager',
    'splunkjs/mvc',
    'underscore',
    'jquery',
    'splunkjs/mvc/simplexml/ready!'
], function(
    TableView,
    EventsViewer,
    SearchManager,
    mvc,
    _,
    $
) {
    var tokens_submitted = mvc.Components.getInstance('submitted');
    var tokens_default = mvc.Components.getInstance('default');

    var currentUser = Splunk.util.getConfigValue("USERNAME");
    tokens_default.set("current_user", currentUser);
    tokens_submitted.set("current_user", currentUser);

    var MITRE_TACTICS = [
        "Reconnaissance", "Resource Development", "Initial Access", "Execution",
        "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access",
        "Discovery", "Lateral Movement", "Collection", "Command and Control",
        "Exfiltration", "Impact"
    ];
    var STATUSES = ["Suspicious", "Under Investigation", "Malicious", "Benign", "False Positive"];

    var tacticOpts = '<option value="">-- Select --</option>';
    MITRE_TACTICS.forEach(function(t) { tacticOpts += '<option value="'+t+'">'+t+'</option>'; });
    var statusOpts = '<option value="">-- Select --</option>';
    STATUSES.forEach(function(s) { statusOpts += '<option value="'+s+'">'+s+'</option>'; });

    $('body').append(
        '<div id="edit-modal" style="display:none;position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.5);z-index:10000;justify-content:center;align-items:center;">' +
          '<div style="background:#fff;border-radius:8px;padding:24px;width:480px;max-width:90%;box-shadow:0 4px 20px rgba(0,0,0,0.3);">' +
            '<h3 style="margin-top:0;">Edit Event Metadata</h3>' +
            '<label style="font-weight:bold;">Status</label>' +
            '<select id="ed-status" style="width:100%;padding:6px;margin-bottom:12px;">' + statusOpts + '</select>' +
            '<label style="font-weight:bold;">MITRE Tactic</label>' +
            '<select id="ed-tactic" style="width:100%;padding:6px;margin-bottom:12px;">' + tacticOpts + '</select>' +
            '<label style="font-weight:bold;">Description</label>' +
            '<textarea id="ed-desc" rows="4" style="width:100%;padding:6px;margin-bottom:16px;resize:vertical;"></textarea>' +
            '<div style="text-align:right;">' +
              '<button id="ed-cancel" style="padding:8px 16px;margin-right:8px;border:1px solid #ccc;border-radius:4px;background:#f4f4f4;cursor:pointer;">Cancel</button>' +
              '<button id="ed-save" style="padding:8px 16px;border:none;border-radius:4px;background:#5cb85c;color:#fff;cursor:pointer;font-weight:bold;">Save</button>' +
            '</div>' +
          '</div>' +
        '</div>'
    );

    var editEventId = null;

    // Search manager to load existing metadata
    var loadMetaSearch = new SearchManager({
        id: 'load_metadata_search',
        preview: false,
        autostart: false
    });

    function openModal(eventId) {
        editEventId = eventId;
        $('#ed-status').val('');
        $('#ed-tactic').val('');
        $('#ed-desc').val('');
        $('#ed-save').prop('disabled', true).text('Loading...');

        loadMetaSearch.set('search', '| inputlookup flagged_events | search id="' + eventId + '" | head 1');
        loadMetaSearch.startSearch();

        loadMetaSearch.off('search:done');
        loadMetaSearch.on('search:done', function(properties) {
            var resultCount = properties.content.resultCount || 0;
            if (resultCount === 0) {
                $('#ed-save').prop('disabled', false).text('Save');
                return;
            }
            var results = loadMetaSearch.data('results');
            if (results) {
                results.on('data', function() {
                    var rows = results.data().rows;
                    var fields = results.data().fields;
                    if (rows && rows.length > 0) {
                        var row = rows[0];
                        var getField = function(name) {
                            var idx = fields.indexOf(name);
                            return idx !== -1 ? row[idx] : '';
                        };
                        $('#ed-status').val(getField('status'));
                        $('#ed-tactic').val(getField('mitre_tactic'));
                        $('#ed-desc').val(getField('description'));
                    }
                    $('#ed-save').prop('disabled', false).text('Save');
                });
            } else {
                $('#ed-save').prop('disabled', false).text('Save');
            }
        });

        $('#edit-modal').css('display', 'flex');
    }

    $('#ed-cancel').on('click', function() { editEventId = null; $('#edit-modal').hide(); });
    $('#edit-modal').on('click', function(e) { if (e.target === this) { editEventId = null; $(this).hide(); } });

    // Search manager to save metadata
    var saveMetaSearch = new SearchManager({
        id: 'save_metadata_search',
        preview: false,
        autostart: false
    });

    $('#ed-save').on('click', function() {
        if (!editEventId) {
            $('#edit-modal').hide();
            return;
        }

        var desc = $('#ed-desc').val().replace(/"/g, '\\"');
        var tactic = $('#ed-tactic').val();
        var status = $('#ed-status').val();

        var spl = '| inputlookup flagged_events' +
            ' | eval description = if(id="' + editEventId + '", "' + desc + '", description)' +
            ' | eval mitre_tactic = if(id="' + editEventId + '", "' + tactic + '", mitre_tactic)' +
            ' | eval status = if(id="' + editEventId + '", "' + status + '", status)' +
            ' | outputlookup flagged_events';

        saveMetaSearch.set('search', spl);
        saveMetaSearch.startSearch();

        saveMetaSearch.off('search:done');
        saveMetaSearch.on('search:done', function() {
            console.log("KVStore updated successfully");
            var flaggedEl = mvc.Components.getInstance("expand_with_events_flagged");
            if (flaggedEl) {
                var mgr = mvc.Components.get(flaggedEl.settings.get("managerid"));
                if (mgr) { mgr.startSearch(); }
            }
        });

        editEventId = null;
        $('#edit-modal').hide();
    });
    // Capture-phase listener: intercepts before Splunk's drilldown
    document.addEventListener('click', function(e) {
        var el = e.target.closest('.edit-icon');
        if (el) {
            e.stopPropagation();
            e.stopImmediatePropagation();
            e.preventDefault();
            var $td = $(el).closest('td');
            var displayValue = $td.attr('title');
            if (displayValue) {
                openModal(displayValue.slice(0, -2));
            }
        }
    }, true);

    var CustomRangeRenderer = TableView.BaseCellRenderer.extend({
        TRUNCATE_LENGTH: 0,
        canRender: function(cell) {
            return cell.field;
        },
        render: function($container, rowData) {
            var fieldValue = rowData.value;
            var fieldName = rowData.field;
            if (fieldName === "Flag") {
                var displayValue = fieldValue.split("@@")[0];
                if (displayValue.length > this.TRUNCATE_LENGTH) {
                    var truncatedValue = displayValue.substring(0, this.TRUNCATE_LENGTH);
                    if (displayValue.endsWith("|0")) {
                        truncatedValue = truncatedValue + '🏳️';
                    } else {
                        truncatedValue = truncatedValue + '🚩';
                    }

                    var $flagSpan = $('<span class="flag-icon">' + truncatedValue + '</span>');
                    $container.empty().append($flagSpan);

                    // Edit icon for flagged events only
                    if (displayValue.endsWith("|1")) {
                        $container.append('<span class="edit-icon" style="cursor:pointer;margin-left:6px;font-size:14px;" title="Edit">✏️</span>');
                    }

                    $container.attr('title', displayValue);
                    $container.off('click').on('click', function(e) {
                        e.stopPropagation();
                        e.stopImmediatePropagation();
                        e.preventDefault();
                        // Ignore clicks on the edit icon
                        if ($(e.target).hasClass('edit-icon') || $(e.target).closest('.edit-icon').length) {
                            return;
                        }
                        // For flagged events, only allow toggle when clicking the flag icon itself
                        if (displayValue.endsWith("|1") && !$(e.target).hasClass('flag-icon') && !$(e.target).closest('.flag-icon').length) {
                            return;
                        }
 
                        if (tokens_default.get("event_to_add")) {
                            console.log("Action bloquée : une mise à jour est déjà en cours.");
                            return;
                        }
                        var eventToAdd = displayValue.slice(0, -2);
                        tokens_default.set("event_to_add", eventToAdd);
                        tokens_submitted.set("event_to_add", eventToAdd);

                        var toggleSearch = mvc.Components.get('toggle');

                        var $cell = $(e.currentTarget);
                        var $flag = $cell.find('.flag-icon');

                        var currentDisplay = $flag.text();
                        var nextEmoji = currentDisplay.includes("🚩") ? "🏳️" : "🚩";
                        $flag.html(nextEmoji);

                        // Toggle edit icon visibility
                        if (nextEmoji.includes("🚩")) {
                            if ($cell.find('.edit-icon').length === 0) {
                                $cell.append('<span class="edit-icon" style="cursor:pointer;margin-left:6px;font-size:14px;" title="Edit">✏️</span>');
                            }
                        } else {
                            $cell.find('.edit-icon').remove();
                        }

                        if (toggleSearch) {
                            toggleSearch.startSearch();
                        }
                        tokens_default.unset("event_to_add");
                        tokens_submitted.unset("event_to_add");
                        console.log("Click blocked for others. Clean value:");
                    });
                } else {
                    $container.html(displayValue);
                }
            } else {
                $container.html(fieldValue);
            }
        }
    });

    var EventSearchBasedRowExpansionRenderer = TableView.BaseRowExpansionRenderer.extend({
        initialize: function(args) {
            this._searchManager = new SearchManager({
                preview: false
            }, { tokens: true, tokenNamespace: "submitted" });
            this._TableView = new EventsViewer({
                managerid: this._searchManager.name,
                drilldown: 'cell',
                type: "raw"
            });
        },

        canRender: function(rowData) {
            return true;
        },

        render: function($container, rowData) {
            var metadataIndex = -1;
            for (var i = 0; i < rowData.fields.length; i++) {
                if (rowData.fields[i] === "Flag") {
                    metadataIndex = i;
                    break;
                }
            }
            var metadata = (metadataIndex !== -1) ? rowData.values[metadataIndex] : "";
            var metadataParts = metadata.split("|");
            var uid = metadataParts[0] || "";
            var search = `
                index="*" uid="${uid}" earliest="-100d" latest="now" 
                | head 1
                | fields *
            `;
            this._searchManager.set({ search: search });
            $container.append(this._TableView.render().el);
        }
    });

    var local_apps = mvc.Components.get(mvc.Components.get('expand_with_events').settings.get("managerid"));
    var flagged_event = mvc.Components.get(mvc.Components.get('expand_with_events_flagged').settings.get("managerid"));
    mvc.Components.get(mvc.Components.get('toggle').settings.get("managerid")).on('search:done', function() {
        tokens_submitted.unset('event_to_add');
        tokens_default.unset('event_to_add');
        flagged_event.startSearch();
    });

    var tableElement = mvc.Components.getInstance("expand_with_events");
    tableElement.getVisualization(function(tableView) {
        tableView.table.addCellRenderer(new CustomRangeRenderer());
        tableView.render();
        tableView.addRowExpansionRenderer(new EventSearchBasedRowExpansionRenderer());
    });

    var tableElementflagged = mvc.Components.getInstance("expand_with_events_flagged");
    tableElementflagged.getVisualization(function(tableView) {
        tableView.table.addCellRenderer(new CustomRangeRenderer());
        tableView.render();
        tableView.addRowExpansionRenderer(new EventSearchBasedRowExpansionRenderer());
    });

});
