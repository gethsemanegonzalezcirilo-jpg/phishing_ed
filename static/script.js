<script>
let currentFilter = "all";

function filterType(type) {
    currentFilter = type;
    applyFilters();
}

function filterEmails() {
    applyFilters();
}

function applyFilters() {
    const input = document.getElementById("searchInput").value.toLowerCase();
    const rows = document.querySelectorAll("#emailTable tbody tr");

    rows.forEach(row => {
        const text = row.innerText.toLowerCase();
        const label = row.getAttribute("data-label") || "";

        const matchesSearch = text.includes(input);
        const matchesFilter = (currentFilter === "all" || label === currentFilter);

        row.style.display = (matchesSearch && matchesFilter) ? "" : "";
    });
}
</script>