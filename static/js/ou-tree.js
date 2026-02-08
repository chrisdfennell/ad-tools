let selectedOuDn = '';

function toggleChildren(toggleEl) {
    const li = toggleEl.closest('li');
    const children = li.querySelector('.ou-children');
    const icon = toggleEl.querySelector('i');
    if (children) {
        if (children.style.display === 'none') {
            children.style.display = 'block';
            icon.className = 'fas fa-caret-down';
        } else {
            children.style.display = 'none';
            icon.className = 'fas fa-caret-right';
        }
    }
}

function selectOu(el, dn) {
    // Deselect previous
    document.querySelectorAll('.ou-node.selected').forEach(function (n) {
        n.classList.remove('selected');
    });
    el.classList.add('selected');
    selectedOuDn = dn;

    // Update create OU parent
    const createParent = document.getElementById('createOuParent');
    if (createParent) createParent.value = dn;

    // Load contents
    document.getElementById('contentTitle').textContent = 'Loading...';
    fetch('/ous/contents?dn=' + encodeURIComponent(dn))
        .then(function (r) { return r.json(); })
        .then(function (data) {
            if (data.error) {
                document.getElementById('contentTitle').textContent = 'Error';
                document.getElementById('ouContents').innerHTML =
                    '<div class="alert alert-danger">' + data.error + '</div>';
                return;
            }
            renderContents(dn, data);
        })
        .catch(function (err) {
            document.getElementById('contentTitle').textContent = 'Error';
            document.getElementById('ouContents').innerHTML =
                '<div class="alert alert-danger">' + err.message + '</div>';
        });
}

function renderContents(dn, data) {
    document.getElementById('contentTitle').innerHTML =
        '<code>' + dn + '</code>' +
        '<div class="float-end">' +
        '<button class="btn btn-sm btn-outline-danger" onclick="showDeleteOu(\'' + escapeHtml(dn) + '\')">' +
        '<i class="fas fa-trash me-1"></i>Delete OU</button>' +
        '</div>';

    let html = '';

    // Child OUs
    if (data.ous.length > 0) {
        html += '<h6 class="text-muted mt-3"><i class="fas fa-folder me-1"></i>Organizational Units (' + data.ous.length + ')</h6>';
        html += '<div class="list-group mb-3">';
        data.ous.forEach(function (item) {
            html += '<div class="list-group-item d-flex justify-content-between align-items-center">' +
                '<span><i class="fas fa-folder me-2 text-warning"></i>' + escapeHtml(item.name) + '</span>' +
                '<small class="text-muted">' + escapeHtml(item.dn) + '</small></div>';
        });
        html += '</div>';
    }

    // Users
    if (data.users.length > 0) {
        html += '<h6 class="text-muted mt-3"><i class="fas fa-user me-1"></i>Users (' + data.users.length + ')</h6>';
        html += '<div class="list-group mb-3">';
        data.users.forEach(function (item) {
            html += '<div class="list-group-item d-flex justify-content-between align-items-center">' +
                '<span><i class="fas fa-user me-2 text-primary"></i>' + escapeHtml(item.name) +
                (item.sam ? ' <code>' + escapeHtml(item.sam) + '</code>' : '') + '</span>' +
                '<button class="btn btn-sm btn-outline-secondary" onclick="showMove(\'' + escapeHtml(item.dn) + '\')">' +
                '<i class="fas fa-arrows-alt"></i></button></div>';
        });
        html += '</div>';
    }

    // Groups
    if (data.groups.length > 0) {
        html += '<h6 class="text-muted mt-3"><i class="fas fa-layer-group me-1"></i>Groups (' + data.groups.length + ')</h6>';
        html += '<div class="list-group mb-3">';
        data.groups.forEach(function (item) {
            html += '<div class="list-group-item d-flex justify-content-between align-items-center">' +
                '<span><i class="fas fa-layer-group me-2 text-success"></i>' + escapeHtml(item.name) + '</span>' +
                '<button class="btn btn-sm btn-outline-secondary" onclick="showMove(\'' + escapeHtml(item.dn) + '\')">' +
                '<i class="fas fa-arrows-alt"></i></button></div>';
        });
        html += '</div>';
    }

    // Computers
    if (data.computers.length > 0) {
        html += '<h6 class="text-muted mt-3"><i class="fas fa-desktop me-1"></i>Computers (' + data.computers.length + ')</h6>';
        html += '<div class="list-group mb-3">';
        data.computers.forEach(function (item) {
            html += '<div class="list-group-item d-flex justify-content-between align-items-center">' +
                '<span><i class="fas fa-desktop me-2 text-secondary"></i>' + escapeHtml(item.name) + '</span>' +
                '<button class="btn btn-sm btn-outline-secondary" onclick="showMove(\'' + escapeHtml(item.dn) + '\')">' +
                '<i class="fas fa-arrows-alt"></i></button></div>';
        });
        html += '</div>';
    }

    if (!html) {
        html = '<p class="text-muted">This OU is empty.</p>';
    }

    document.getElementById('ouContents').innerHTML = html;
}

function showDeleteOu(dn) {
    document.getElementById('deleteOuDn').value = dn;
    document.getElementById('deleteOuName').textContent = dn;
    new bootstrap.Modal(document.getElementById('deleteOuModal')).show();
}

function showMove(objectDn) {
    document.getElementById('moveObjectDn').value = objectDn;
    document.getElementById('moveNewOuDn').value = selectedOuDn;
    new bootstrap.Modal(document.getElementById('moveModal')).show();
}

function escapeHtml(str) {
    var div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}
