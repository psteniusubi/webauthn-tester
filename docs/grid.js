function CreateGrid(definition, onchange) {
	for(var i in definition) {
		var div = $("<div>");
		var property = definition[i];
		
		if(!property.id) property.id = "grid" + i;
		
		if(property.title !== "") {
			var left = $("<div>")
				.addClass("left");			

			if(property.id && property.input) {
				var label = $("<label>")
					.attr("for", property.id)
					.append(property.title || property.id);
				left.append(label);	
			} else {
				left.append(property.title || property.id);
			}

			if(property.href) {
				var a = $("<a>")
					.attr("target", "_blank")				
					.attr("href", property.href)
					.text("w3c");
				var span = $("<span>")
					.addClass("w3c")
					.append("[")
					.append(a)
					.append("]");
				left.append(span);
			} 

			div.append(left);
		}
		
		if(property.input) {
			var right = $("<div>")
				.addClass("right");
			var input;
			var change = null;
			switch(property.input.type) {
			case "text":
				input = $("<input>")
					.attr("type", "text")
					.attr("id", property.id);
				change = "input";
				break;
			case "textarea":
				input = $("<textarea>")
					.attr("rows", "2")
					.attr("id", property.id);
				right.addClass("wide");
				change = "input";
				break;
			case "select":
				input = $("<select>")
					.attr("id", property.id);
				change = "change";
				Object.values(property.input.values).forEach(v => {
					var option = $("<option>").text(v);
					input.append(option);
				});
				break;
			case "button":
				input = $("<input>")
					.attr("type", "button")
					.attr("value", property.input.value)
					.attr("id", property.id);
				break;
			}
			if(property.bind) {
				property.bind(input);
			}
			if(property.input.readonly) {
				input.attr("readonly", "readonly");
			} else if(change && onchange) {
				input.on(change, onchange);
				div.addClass("input");
			}
			right.append(input);
			div.append(right);
		}

		$("body").append(div);
	}
}