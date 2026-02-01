require([
    'splunkjs/mvc/tableview',
    'splunkjs/mvc/eventsviewerview',
    'splunkjs/mvc/searchmanager',
    'splunkjs/mvc',
    'underscore',
    'splunkjs/mvc/simplexml/ready!'
], function(
    TableView,
    EventsViewer,
    SearchManager,
    mvc,
    _
) {
    var tokens_submitted = mvc.Components.getInstance('submitted');
	var tokens_default = mvc.Components.getInstance('default');

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
                    if (displayValue.endsWith("|0")){
                        truncatedValue = truncatedValue + '🏳️'
                    }else{
                        truncatedValue = truncatedValue + '🚩'
                    }
                    $container.html(truncatedValue);
                    $container.attr('title', displayValue);
                    $container.off('click').on('click', function(e) {
                        e.stopPropagation();
                        e.stopImmediatePropagation();
                        e.preventDefault();
                        if (tokens_default.get("event_to_add")) {
                            console.log("Action bloquée : une mise à jour est déjà en cours.");
                            return; 
                        }
                        var eventToAdd = displayValue.slice(0, -2);                      
                        tokens_default.set("event_to_add", eventToAdd);
                        tokens_submitted.set("event_to_add", eventToAdd);

                        var toggleSearch = mvc.Components.get('toggle'); 
                        

                        var $cell = $(e.currentTarget);

                        var currentDisplay = $cell.text();
                        
                        var nextEmoji = currentDisplay.includes("🚩") ? "🏳️" : "🚩";
                        
                        $cell.html(nextEmoji); 
                        
                
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
            //this._chartView = new ChartView({
            //    managerid: 'details-search-manager',
            //    'charting.legend.placement': 'none'
            //});
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
            var _bkt = metadataParts[0] || "";
            var _cd = metadataParts[1] || "";
            var host = metadataParts[2] || "";
            var index = metadataParts[3] || "";
            var source = metadataParts[4] || "";
            var _time = metadataParts[5] || "";

            var timeAsNumber = parseFloat(_time);

            var timePlusOne = timeAsNumber + 1;
            var timeMinusOne = timeAsNumber - 1;

            var search = `
                index="${index}" source="${source}" host="${host}" earliest="${timeMinusOne}" latest="${timePlusOne}"
                | where _bkt="${_bkt}" AND _cd="${_cd}"
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
	    // local_apps.startSearch();
        // flagged_event.startSearch();
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