/* Lightweight i18n for Fraud-Checker-BD. Bengali (bn) is the default.
   - Static text: add data-i18n / data-i18n-ph / data-i18n-aria attributes.
   - Dynamic (JS) text: use FC.t('key').
   Loaded AFTER shared.js so it extends the existing FC object. */
(function (global) {
  'use strict';
  var STORE = 'fc_lang';

  var I18N = {
    en: {
      // brand / nav / common
      'nav.admin': 'Admin Panel', 'nav.back_search': '← Back to Search', 'nav.search': 'Search',
      'common.loading': 'Loading…', 'common.close': 'Close', 'common.cancel': 'Cancel', 'common.save': 'Save changes',
      'common.na': 'N/A', 'common.not_provided': 'Not provided', 'common.report_another': 'Report Another Incident',
      'common.network_error': 'Network error', 'common.error': 'Error',

      // index — hero / CTA
      'index.hero.title': 'Protect Yourself From Fraud',
      'index.hero.sub': 'A Community-Driven Fraud Database for Bangladesh — check before you trust.',
      'index.cta.title': 'Are you a victim of a scam?',
      'index.cta.body': 'Report the incident and help protect others from the same fraudster. Your report could save someone from losing their life savings.',
      'index.cta.button': 'Report an Incident Now',
      // public stats
      'index.stats.reports': 'Verified reports', 'index.stats.loss': 'Reported losses',
      'index.stats.fraudsters': 'Fraudster profiles', 'index.stats.new30': 'New in last 30 days',
      // search
      'index.search.title': 'Search Fraud Database',
      'index.search.sub': 'Search by imposter name, nickname, phone number, NID, scam type, location, and more',
      'index.search.ph': 'Enter name, phone, NID, location, or scam type…',
      'index.search.button': 'Search',
      'index.search.hint': '💡 Search for: imposter name, nickname, phone, NID, GD number, scam type, description, location',
      'index.cat.all': 'All categories',
      'index.sort.recent': 'Sort: Most recent', 'index.sort.loss': 'Sort: Highest loss',
      'index.loadmore': 'Load more results',
      // categories + submit option labels
      'cat.ticket': 'Ticket Fraud', 'cat.hotel': 'Hotel Booking', 'cat.tour': 'Tour/Travel', 'cat.reservation': 'Reservation', 'cat.ecommerce': 'E-Commerce', 'cat.mobile_banking': 'Mobile Banking', 'cat.job': 'Job Offer', 'cat.loan': 'Loan/Investment', 'cat.romance': 'Romance', 'cat.other': 'Other',
      'submit.scam_select': '-- Select Scam Type --', 'submit.loss_select': '-- Select Loss Item --',
      'sopt.ticket': 'Ticket Fraud (Flight, Movie, Event)', 'sopt.hotel': 'Hotel Booking Scam', 'sopt.tour': 'Tour Group / Travel Fraud', 'sopt.reservation': 'Restaurant/Event Reservation Scam', 'sopt.ecommerce': 'E-Commerce / Online Shopping', 'sopt.mobile_banking': 'Mobile Banking / Payment Fraud', 'sopt.job': 'Job Offer Scam', 'sopt.loan': 'Loan / Investment Scam', 'sopt.romance': 'Romance / Dating Scam', 'sopt.other': 'Other (please specify below)',
      'lopt.money': 'Money / Cash', 'lopt.reputation': 'Reputation / Trust', 'lopt.device': 'Device (Phone, Laptop, etc.)', 'lopt.personal': 'Personal Data / Information', 'lopt.jewelry': 'Jewelry / Valuables', 'lopt.documents': 'Important Documents', 'lopt.other': 'Other (please specify below)',
      // empty states
      'index.nosearch.title': 'Start Searching to Find Fraud Information',
      'index.nosearch.body': 'Use the search box above to look for known scammers and fraudsters in our verified database.',
      'index.nosearch.q': "Haven't found what you're looking for?",
      'index.nosearch.help': 'If you know of a scammer not in our database, report them now and help others stay safe.',
      'index.nosearch.button': 'Add an Incident Report',
      'index.noresults.title': 'No Matching Fraud Reports Found',
      'index.noresults.body': "That's good news! We haven't found any verified fraud reports matching your search.",
      'index.noresults.q': 'Do you know of this person as a scammer?',
      'index.noresults.help': 'Help the community by reporting your experience. Your report could prevent others from being scammed.',
      'index.noresults.button': 'Report This Incident',
      // features
      'index.features.title': 'Why Fraud-Checker-BD?',
      'index.feat1.title': 'Verified Database', 'index.feat1.body': 'Check names, phone numbers, and scam details from verified reports',
      'index.feat2.title': 'Community Protection', 'index.feat2.body': 'Real victims sharing their experiences to prevent others from being scammed',
      'index.feat3.title': 'Report & Help', 'index.feat3.body': 'Share your experience and help others identify dangerous scammers',
      // footer
      'footer.tagline': 'A community-driven fraud reporting & search platform for Bangladesh.',
      'footer.search': 'Search', 'footer.report': 'Report Incident', 'footer.admin': 'Admin Panel',
      'footer.rights': '© 2026 Fraud-Checker-BD. All rights reserved.',
      // index modal + dynamic cards
      'index.modal.title': 'Fraud Event Details', 'index.modal.full': 'View Full Details',
      'card.verified': 'REPORTED', 'card.loss': 'Loss Amount', 'card.item': 'Item', 'card.location': 'Location',
      'card.phone_hidden': 'Phone not shown', 'card.click': 'Click for details →',
      'card.unknown_scam': 'Unknown Scam', 'card.unknown_imposter': 'Unknown Imposter', 'card.location_na': 'Location not provided',
      'modal.fraudster': '🚩 REPORTED — alleged, pending verification', 'modal.nickname': 'Nickname', 'modal.fraud_details': '📋 Fraud Details',
      'modal.scam_type': 'Scam Type', 'modal.item_lost': 'Item Lost', 'modal.desc': '📝 Incident Description',
      'modal.no_desc': 'No description provided', 'modal.contact': '📞 Contact Information', 'modal.phones': 'Phone Number(s)',
      'modal.reported_by': '👤 Reported By', 'modal.reported_on': 'Reported on', 'modal.anonymous': 'Anonymous',
      'modal.reporter_hidden': 'Hidden (Reporter chose not to display)',
      'results.found_one': '{n} Fraud Report found', 'results.found_many': '{n} Fraud Reports found',
      'verdict.has': '⚠️ This number appears in {n} fraud report(s). Review the details below before trusting it.',
      'verdict.none': '✅ No fraud reports found for this number. Stay cautious — absence of a report is not a guarantee.',
      'toast.enter_search': 'Please enter a search term',
      'toast.search_error': 'Search error', 'toast.event_not_found': 'Event not found',
      'toast.detail_error': 'Error loading event details',

      // submit
      'submit.title': 'Submit Fraud Incident Report', 'submit.subtitle': 'All submissions undergo administrative review before public listing',
      'submit.sec1': 'Imposter Personal Details', 'submit.sec2': 'Scam Details', 'submit.sec3': 'Reporter Information',
      'submit.picture': 'Imposter Picture', 'submit.picture_hint': 'Upload a photo of the imposter (JPG, PNG, max 5MB)',
      'submit.name': 'Imposter Name', 'submit.name_hint': 'Full name of the fraudster as known',
      'submit.nickname': 'Nickname / Pseudonym', 'submit.nickname_hint': 'Also known as (optional)',
      'submit.phone': 'Imposter Phone Number', 'submit.phone_hint': 'Format: +880XXXXXXXXX or 01XXXXXXXXX',
      'submit.nid': 'NID / ID Card Number', 'submit.nid_hint': 'National ID, passport, or other identity document number',
      'submit.social': 'Social Media Account', 'submit.social_hint': "Link to fraudster's social media profile (optional)",
      'submit.address': 'Imposter Address', 'submit.address_hint': 'Last known address or location',
      'submit.scam_type': 'Type of Scam', 'submit.scam_other': 'Specify other type…',
      'submit.loss_item': 'Loss Item / Property', 'submit.loss_other': 'Specify other item…',
      'submit.loss_amount': 'Value of Loss (BDT)', 'submit.loss_amount_hint': 'Estimated loss amount in Bangladeshi Taka',
      'submit.desc': 'Description of the Scam', 'submit.desc_hint': 'Detailed explanation (30-500 characters)',
      'submit.desc_ph': 'Describe what happened…', 'submit.char_count': 'Character count:', 'submit.char_warn': 'Minimum 30 characters required',
      'submit.proof': 'Proof of the Scam', 'submit.proof_hint': 'Screenshots, images, videos or documents (max 20 files total, 10MB each)',
      'submit.proof_selected': 'Selected: 0 file(s)', 'submit.proof_warn': 'Maximum 20 files allowed. Please remove some files.',
      'submit.scam_loc': 'Location of Scam', 'submit.scam_loc_hint': 'Where the scam took place (online platform, location, etc.)',
      'submit.scam_loc_ph': 'e.g., Facebook, OLX, WhatsApp, etc.',
      'submit.gd': 'General Diary (GD) Number', 'submit.gd_hint': 'Police GD/FIR number if filed',
      'submit.alt_phone': 'Alternative Phone Number of Scammer', 'submit.alt_phone_hint': 'Other phone numbers used by the fraudster',
      'submit.your_name': 'Your Name', 'submit.your_name_hint': 'Full name or pseudonym (can be hidden from public)',
      'submit.your_phone': 'Your Phone Number', 'submit.your_phone_hint': 'For follow-up purposes (optional)',
      'submit.your_email': 'Your Email', 'submit.your_email_hint': 'For updates and notifications (optional)',
      'submit.hide': 'Hide my information from public event list', 'submit.hide_hint': 'If checked, your report will be marked as "Anonymous" publicly',
      'submit.back': '← Back to Search', 'submit.button': 'Submit Report', 'submit.required': '(required)',
      'submit.success.title': 'Report submitted', 'submit.success.body': 'Thank you — your report will be reviewed by our team before it appears publicly.',
      'submit.success.ref': 'Reference ID:', 'submit.success.search': 'Search the database', 'submit.success.another': 'Report another',
      'submit.toast.success': '✓ Report submitted', 'submit.toast.proof_required': 'Please upload at least one proof file',
      'submit.proof_selected_n': 'Selected: {n} file(s)', 'submit.dup': '⚠️ This number/NID already has {n} report(s). You can still submit — it adds corroboration.',
      'submit.phone_invalid': 'Invalid phone format', 'submit.toast.invalid_alt': 'Invalid alternative phone number format', 'submit.toast.invalid_rphone': 'Invalid reporter phone number format',
      'submit.toast.desc_len': 'Description must be between 30 and 500 characters', 'submit.toast.max_alt': 'Maximum 5 alternative phone numbers allowed', 'submit.toast.max_files': 'Maximum 20 files total reached', 'submit.toast.error_prefix': 'Error', 'submit.toast.draft_restored': 'Draft restored', 'submit.toast.submit_error': 'Submission error',

      // event detail
      'detail.loading': 'Loading event details…', 'detail.subtitle': 'Reported — allegation pending verification', 'detail.loss': 'Loss Amount', 'detail.scam_type': 'Scam Type', 'detail.location': 'Location',
      'detail.trust.count': 'Reports of this number', 'detail.trust.first': 'First reported', 'detail.trust.last': 'Most recent report',
      'detail.fraud_details': '📋 Fraud Details', 'detail.item_lost': 'Item Lost', 'detail.gd': 'GD Number (Police)', 'detail.desc': 'Description',
      'detail.imposter': '👤 Imposter Profile Details', 'detail.full_name': 'Full Name', 'detail.nickname': 'Nickname / Pseudonym',
      'detail.primary_phone': 'Primary Phone', 'detail.nid': 'NID / ID Number', 'detail.alt_phones': 'Alternative Phone Numbers',
      'detail.address': 'Address / Location', 'detail.social': 'Social Media Account', 'detail.profile_link': '👤 View Full Fraudster Profile →',
      'detail.evidence': '📸 Evidence & Proofs', 'detail.reported_by': '📢 Reported By', 'detail.share': '🔗 Share This Report',
      'detail.share_body': 'Help others stay safe by sharing this fraud report:', 'detail.copy': 'Copy Link',
      'detail.dispute.title': '⚖️ Is this report wrong?',
      'detail.dispute.body': 'If you are the person named here, or you have evidence this report is inaccurate, submit a dispute and our moderators will review it.',
      'detail.dispute.button': 'Dispute this report', 'detail.dispute.reason_ph': 'Explain why this report is inaccurate (20–1000 characters)…',
      'detail.dispute.contact_ph': 'Your contact (optional, for follow-up)', 'detail.dispute.submit': 'Submit dispute',
      'detail.notfound.title': 'Event Not Found', 'detail.notfound.body': 'This fraud report could not be found or may have been removed.',
      'detail.notfound.button': 'Return to Search',
      'detail.reporter_public': 'Reporter details are public', 'detail.reporter_private': 'Reporter information is private (per reporter request)',
      'detail.not_filed': 'Not filed', 'detail.gd_not_filed': 'Not filed', 'detail.download': 'Open / Download', 'detail.download_video': 'Open / Download Video',
      'toast.link_copied': 'Link copied to clipboard', 'toast.copy_fail': 'Could not copy the link', 'toast.dispute_min': 'Please provide at least 20 characters.',

      // imposter profile
      'profile.loading': 'Loading imposter profile…', 'profile.verified_profile': 'Reported — community allegations, pending verification',
      'profile.total': 'Total Incidents', 'profile.total_loss': 'Total Loss', 'profile.last_active': 'Last Active', 'profile.status': 'Profile Status',
      'profile.status_verified': '🚩 Reported', 'profile.contact': '📱 Known Contact Information', 'profile.details': 'ℹ️ Profile Details',
      'profile.history': '🔴 Fraud Incident History', 'profile.warn.title': '⚠️ Be Cautious',
      'profile.warn.body': 'If you encounter this person, do not send money, share personal information, or engage in any financial transactions. Report any new incidents immediately.',
      'profile.warn.button': 'Report a New Incident with This Person',
      'profile.notfound.title': 'Profile Not Found', 'profile.notfound.body': 'This imposter profile could not be found or may have been removed.',
      'profile.no_incidents': 'No public incidents are linked to this profile yet.',
      'profile.full_name': 'Full Name', 'profile.nickname': 'Nickname / Pseudonym', 'profile.known_address': 'Known Address', 'profile.social': 'Social Media',
      'profile.unknown': 'Unknown', 'profile.unknown_fraudster': 'Unknown Fraudster', 'profile.phones': 'Phone Numbers ({n})', 'profile.no_phones': 'No phone numbers found', 'profile.nids': 'NID Numbers ({n})',

      // admin
      'admin.title': 'Fraud-Checker-BD Admin', 'admin.portal': 'Secure Moderator Access Portal',
      'admin.user_ph': 'Admin Username', 'admin.pass_ph': 'Password', 'admin.login': 'Login', 'admin.logout': 'Logout',
      'admin.panel.title': 'Fraud-Checker-BD Control Panel', 'admin.panel.sub': 'Central Administration & Moderation Hub',
      'admin.tab.live': '✓ Live Events', 'admin.tab.pending': '⏳ Pending Events', 'admin.tab.deleted': '✕ Deleted Events',
      'admin.tab.imposters': '👥 Imposter List', 'admin.tab.reporters': '📋 Reporter List', 'admin.tab.audit': '📜 Audit Log',
      'admin.tab.disputes': '⚖️ Disputes', 'admin.tab.admins': '🔑 Admin List',
      'admin.filter_ph': 'Filter the current list…',
      'admin.live.title': 'Live Fraud Events', 'admin.live.sub': 'Approved events currently in the public fraud database',
      'admin.pending.title': 'Pending Fraud Events', 'admin.pending.sub': 'Events awaiting administrative review and approval',
      'admin.deleted.title': 'Deleted Fraud Events', 'admin.deleted.sub': 'Rejected events with reason and timestamp',
      'admin.imposters.title': 'Fraud Imposter Database', 'admin.imposters.sub': 'Complete list of identified and verified fraudsters',
      'admin.reporters.title': 'Reporter Contributions', 'admin.reporters.sub': 'Community members and their fraud report submissions',
      'admin.audit.title': 'Moderation Audit Log', 'admin.audit.sub': 'Every approve / reject / delete / edit action, most recent first',
      'admin.disputes.title': 'Disputes', 'admin.disputes.sub': 'Right-of-reply submissions contesting a published report',
      'admin.admins.title': 'Admin Management', 'admin.admins.sub': 'System administrators (only a superuser can add or remove accounts)',
      'admin.add_admin': 'Add an admin', 'admin.username_ph': 'Username', 'admin.password_ph2': 'Password (min 8)', 'admin.create': 'Create',
      'admin.bulk.approve': 'Approve selected', 'admin.bulk.reject': 'Reject selected', 'admin.bulk.selected': '{n} selected',
      'admin.modal.title': 'Event Details', 'admin.approve': 'Approve', 'admin.reject': 'Reject', 'admin.delete': 'Delete',
      'admin.reapprove': 'Re-approve', 'admin.edit': 'Edit', 'admin.remove': 'Remove', 'admin.select': 'select',
      'admin.empty.live': 'No live events at this time', 'admin.empty.pending': 'No pending events', 'admin.empty.deleted': 'No deleted events',
      'admin.empty.imposters': 'No fraudsters in database', 'admin.empty.reporters': 'No reporters yet', 'admin.empty.audit': 'No audit entries yet',
      'admin.empty.disputes': 'No disputes', 'admin.empty.admins': 'No admins.', 'admin.loadmore': 'Load more',
      'admin.stat.pending': 'Pending', 'admin.stat.live': 'Live', 'admin.stat.rejected': 'Rejected', 'admin.stat.fraudsters': 'Fraudsters', 'admin.stat.loss': 'Total loss', 'admin.stat.new7': 'New (7d)',
      'admin.live_since': 'Live since {t}', 'admin.submitted': 'Submitted: {t}', 'admin.rejected_ago': 'Rejected {t}', 'admin.reason': 'Reason: {x}', 'admin.approved_at': 'Approved: {t}', 'admin.awaiting': 'Awaiting action…',
      'admin.loss': 'Loss', 'admin.scams': 'Scams', 'admin.total_loss': 'Total Loss', 'admin.last_active': 'Last Active', 'admin.reports': 'Reports', 'admin.approved_n': 'Approved', 'admin.first_report': 'First Report', 'admin.view_profile': '↗ view profile', 'admin.not_specified': 'Not specified',
      'admin.badge.live': 'LIVE', 'admin.badge.pending': 'PENDING', 'admin.badge.rejected': 'REJECTED', 'admin.card.select': 'select',
      'admin.m.imposter': '👤 Imposter Details', 'admin.m.scam': '🎯 Scam Details', 'admin.m.evidence': '📸 Evidence', 'admin.m.reporter': '📋 Reporter Details', 'admin.m.status': '📊 Event Status',
      'admin.f.name': 'Name', 'admin.f.nickname': 'Nickname', 'admin.f.phone': 'Phone', 'admin.f.nid': 'NID', 'admin.f.address': 'Address', 'admin.f.social': 'Social Media', 'admin.f.altphones': 'Alternative Phones', 'admin.f.type': 'Type', 'admin.f.lossitem': 'Loss Item', 'admin.f.lossamount': 'Loss Amount', 'admin.f.location': 'Location', 'admin.f.gd': 'GD Number', 'admin.f.desc': 'Description', 'admin.f.visibility': 'Visibility', 'admin.f.email': 'Email', 'admin.f.submitted': 'Submitted', 'admin.f.status': 'Status', 'admin.f.approved': 'Approved', 'admin.f.rejected': 'Rejected', 'admin.f.reason': 'Reason', 'admin.f.photo': 'Imposter Photo', 'admin.f.prooffiles': 'Proof Files ({n})',
      'admin.no_proofs': 'No proof files were attached.', 'admin.no_photo': 'No imposter photo uploaded.',
      'admin.btn.close': 'Close', 'admin.btn.cancel': 'Cancel', 'admin.btn.save': 'Save changes',
      'admin.au.by': 'by', 'admin.au.fields': 'fields:',
      'admin.dc.re': 'Re:', 'admin.dc.contact': 'Contact:', 'admin.dc.resolve': 'Mark resolved', 'admin.dc.dismiss': 'Dismiss', 'admin.dc.note': 'Note:', 'admin.st.open': 'open', 'admin.st.resolved': 'resolved', 'admin.st.dismissed': 'dismissed',
      'admin.am.created': 'Created', 'admin.am.remove': 'Remove',
      'admin.edit.title': '✏️ Edit event', 'admin.edit.desc': 'Description (30–500 chars)',
      'admin.toast.session': 'Your admin session has expired. Please log in again.', 'admin.toast.network': 'Network error', 'admin.toast.login_err': 'Login error', 'admin.toast.invalid_creds': 'Invalid credentials', 'admin.toast.event_not_found': 'Event not found', 'admin.toast.ureq': 'Username and password are required', 'admin.toast.confirm_remove': 'Remove admin "{u}"?',
      'admin.reject_prompt': 'Enter rejection reason:', 'admin.delete_confirm': 'Are you sure you want to delete this event?', 'admin.note_prompt': 'Optional note:', 'admin.bulk_reject_prompt': 'Rejection reason for {n} event(s):', 'admin.bulk_confirm_approve': 'Approve {n} event(s)?', 'admin.bulk_confirm_reject': 'Reject {n} event(s)?', 'admin.selected_n': '{n} selected', 'admin.bulk_done_approve': '{ok}/{total} approved', 'admin.bulk_done_reject': '{ok}/{total} rejected', 'admin.au.action': 'action', 'admin.au.system': 'system',

      // allegation framing + new features (EN)
      'common.allegation': '⚠️ Community allegation — reported by a user and pending independent verification. Not a proven fact or a court finding.',
      'index.risk.title': 'Am I being scammed? Check a number',
      'index.risk.sub': 'Paste a phone or bKash/Nagad number to see if it has been reported.',
      'index.risk.check': 'Check now', 'index.risk.reports': '{n} report(s)', 'index.risk.clean': 'No reports found yet — stay cautious.',
      'index.risk.foreign': 'This is a foreign / non-standard number. Banks and MFS never call from these.',
      'index.recent.title': 'Recently reported', 'index.recent.sub': 'Latest approved community fraud reports',
      'submit.mfs': '💸 Money trail (bKash / Nagad / bank)',
      'submit.mfs_hint': 'If you sent money, add where it went — the receiving wallet/account is the strongest way to catch a scammer who changes SIMs.',
      'submit.mfs_provider': '-- MFS provider --', 'submit.mfs_wallet': 'Receiving wallet number', 'submit.mfs_trxid': 'Transaction ID (TrxID)', 'submit.bank': 'Bank account (name / number)',
      'submit.paste': '⚡ Quick start — paste the scam SMS / message',
      'submit.paste_hint': "We'll pull out phone numbers, wallet numbers, transaction IDs and amounts for you. You can edit everything before submitting.",
      'submit.paste_ph': 'Paste the message you received…', 'submit.paste_btn': 'Extract details',
      'submit.paste.phone': 'phone', 'submit.paste.trxid': 'transaction ID', 'submit.paste.desc': 'description',
      'submit.paste.done': 'Filled: {items}. Please review before submitting.', 'submit.paste.none': 'Nothing recognisable found — please fill the form manually.',
      'submit.consent': 'I experienced this first-hand (or witnessed it), the evidence is genuine, and I understand this report names a real person and may be reviewed by moderators.',
      'submit.consent_pii': '⚠ Your description appears to contain your OWN phone/NID — please remove your personal details before submitting.',
      'submit.toast.consent': 'Please confirm the report is truthful and first-hand.',
      'submit.strength': 'Report strength', 'submit.strength.add': 'Add {items} to strengthen this report.', 'submit.strength.good': 'Strong report — thank you!',
      'submit.need.proof': 'more proof files', 'submit.need.photo': 'a photo', 'submit.need.gd': 'a GD number', 'submit.need.nid': 'the NID', 'submit.need.desc': 'a fuller description', 'submit.need.mfs': 'the money trail',
      'detail.risk': 'Risk level', 'detail.share.wa': 'WhatsApp', 'detail.share.fb': 'Facebook', 'detail.share.native': 'Share',
      'detail.share.msg': '⚠️ Fraud alert from Fraud-Checker-BD (community allegation, pending verification):',
      'detail.golden.title': '⏱️ Sent money just now? Act fast',
      'detail.golden.body': 'MFS transfers can sometimes be frozen if you contact the provider immediately. Quote the receiving wallet, TrxID, amount and time.',
      'detail.golden.bkash': 'bKash: 16247', 'detail.golden.nagad': 'Nagad: 16167', 'detail.golden.police': 'Police / emergency: 999 · Cyber help: report to CID Cyber Police Centre',
      'admin.change_pw': 'Change Password', 'admin.pw.title': 'Change your password', 'admin.pw.current': 'Current password', 'admin.pw.new': 'New password (min 8)', 'admin.pw.save': 'Change password', 'admin.pw.required': 'Both fields are required.', 'admin.pw.must_change': 'You are using the default password. Please change it now.',
      'admin.toast.media_err': 'Could not load the file.', 'admin.sort.evidence': '⚠ Sort: weakest evidence first', 'admin.evidence': 'Evidence'
    },
    bn: {
      'nav.admin': 'অ্যাডমিন প্যানেল', 'nav.back_search': '← খোঁজে ফিরে যান', 'nav.search': 'খুঁজুন',
      'common.loading': 'লোড হচ্ছে…', 'common.close': 'বন্ধ করুন', 'common.cancel': 'বাতিল করুন', 'common.save': 'পরিবর্তন সংরক্ষণ করুন',
      'common.na': 'নেই', 'common.not_provided': 'দেওয়া হয়নি', 'common.report_another': 'আরেকটি ঘটনা রিপোর্ট করুন',
      'common.network_error': 'নেটওয়ার্ক সমস্যা', 'common.error': 'সমস্যা',

      'index.hero.title': 'প্রতারণা থেকে নিজেকে রক্ষা করুন',
      'index.hero.sub': 'বাংলাদেশের জন্য একটি কমিউনিটি-চালিত প্রতারণা ডেটাবেজ — বিশ্বাস করার আগে যাচাই করুন।',
      'index.cta.title': 'আপনি কি প্রতারণার শিকার?',
      'index.cta.body': 'ঘটনাটি রিপোর্ট করুন এবং একই প্রতারকের হাত থেকে অন্যদের রক্ষা করতে সাহায্য করুন। আপনার রিপোর্ট কারও সারা জীবনের সঞ্চয় বাঁচাতে পারে।',
      'index.cta.button': 'এখনই একটি ঘটনা রিপোর্ট করুন',
      'index.stats.reports': 'যাচাইকৃত রিপোর্ট', 'index.stats.loss': 'রিপোর্টকৃত ক্ষতি',
      'index.stats.fraudsters': 'প্রতারকের প্রোফাইল', 'index.stats.new30': 'গত ৩০ দিনে নতুন',
      'index.search.title': 'প্রতারণা ডেটাবেজে খুঁজুন',
      'index.search.sub': 'প্রতারকের নাম, ডাকনাম, ফোন নম্বর, এনআইডি, প্রতারণার ধরন, অবস্থান ইত্যাদি দিয়ে খুঁজুন',
      'index.search.ph': 'নাম, ফোন, এনআইডি, অবস্থান বা প্রতারণার ধরন লিখুন…',
      'index.search.button': 'খুঁজুন',
      'index.search.hint': '💡 যা দিয়ে খুঁজবেন: প্রতারকের নাম, ডাকনাম, ফোন, এনআইডি, জিডি নম্বর, প্রতারণার ধরন, বিবরণ, অবস্থান',
      'index.cat.all': 'সব ধরন',
      'index.sort.recent': 'সাজান: সর্বশেষ', 'index.sort.loss': 'সাজান: সর্বোচ্চ ক্ষতি',
      'index.loadmore': 'আরও ফলাফল দেখুন',
      'cat.ticket': 'টিকেট প্রতারণা', 'cat.hotel': 'হোটেল বুকিং', 'cat.tour': 'ট্যুর/ভ্রমণ', 'cat.reservation': 'রিজার্ভেশন', 'cat.ecommerce': 'ই-কমার্স', 'cat.mobile_banking': 'মোবাইল ব্যাংকিং', 'cat.job': 'চাকরির অফার', 'cat.loan': 'ঋণ/বিনিয়োগ', 'cat.romance': 'রোমান্স', 'cat.other': 'অন্যান্য',
      'submit.scam_select': '-- প্রতারণার ধরন নির্বাচন করুন --', 'submit.loss_select': '-- যা হারিয়েছেন তা নির্বাচন করুন --',
      'sopt.ticket': 'টিকেট প্রতারণা (ফ্লাইট, মুভি, ইভেন্ট)', 'sopt.hotel': 'হোটেল বুকিং প্রতারণা', 'sopt.tour': 'ট্যুর গ্রুপ / ভ্রমণ প্রতারণা', 'sopt.reservation': 'রেস্টুরেন্ট/ইভেন্ট রিজার্ভেশন প্রতারণা', 'sopt.ecommerce': 'ই-কমার্স / অনলাইন শপিং', 'sopt.mobile_banking': 'মোবাইল ব্যাংকিং / পেমেন্ট প্রতারণা', 'sopt.job': 'চাকরির অফার প্রতারণা', 'sopt.loan': 'ঋণ / বিনিয়োগ প্রতারণা', 'sopt.romance': 'রোমান্স / ডেটিং প্রতারণা', 'sopt.other': 'অন্যান্য (নিচে উল্লেখ করুন)',
      'lopt.money': 'টাকা / নগদ', 'lopt.reputation': 'সুনাম / বিশ্বাস', 'lopt.device': 'ডিভাইস (ফোন, ল্যাপটপ ইত্যাদি)', 'lopt.personal': 'ব্যক্তিগত তথ্য', 'lopt.jewelry': 'গয়না / মূল্যবান জিনিস', 'lopt.documents': 'জরুরি কাগজপত্র', 'lopt.other': 'অন্যান্য (নিচে উল্লেখ করুন)',
      'index.nosearch.title': 'প্রতারণার তথ্য জানতে খোঁজা শুরু করুন',
      'index.nosearch.body': 'আমাদের যাচাইকৃত ডেটাবেজে পরিচিত প্রতারকদের খুঁজতে উপরের সার্চ বক্সটি ব্যবহার করুন।',
      'index.nosearch.q': 'যা খুঁজছেন তা পাননি?',
      'index.nosearch.help': 'আপনি যদি এমন কোনো প্রতারককে চেনেন যা আমাদের ডেটাবেজে নেই, এখনই রিপোর্ট করুন এবং অন্যদের নিরাপদ থাকতে সাহায্য করুন।',
      'index.nosearch.button': 'একটি ঘটনা রিপোর্ট যোগ করুন',
      'index.noresults.title': 'মিল আছে এমন কোনো প্রতারণার রিপোর্ট পাওয়া যায়নি',
      'index.noresults.body': 'এটা ভালো খবর! আপনার খোঁজের সাথে মিল আছে এমন কোনো যাচাইকৃত প্রতারণার রিপোর্ট পাওয়া যায়নি।',
      'index.noresults.q': 'আপনি কি এই ব্যক্তিকে প্রতারক হিসেবে জানেন?',
      'index.noresults.help': 'আপনার অভিজ্ঞতা রিপোর্ট করে কমিউনিটিকে সাহায্য করুন। আপনার রিপোর্ট অন্যদের প্রতারণা থেকে বাঁচাতে পারে।',
      'index.noresults.button': 'এই ঘটনাটি রিপোর্ট করুন',
      'index.features.title': 'কেন Fraud-Checker-BD?',
      'index.feat1.title': 'যাচাইকৃত ডেটাবেজ', 'index.feat1.body': 'যাচাইকৃত রিপোর্ট থেকে নাম, ফোন নম্বর ও প্রতারণার বিবরণ যাচাই করুন',
      'index.feat2.title': 'কমিউনিটির সুরক্ষা', 'index.feat2.body': 'সত্যিকারের ভুক্তভোগীরা তাদের অভিজ্ঞতা শেয়ার করছেন যাতে অন্যরা প্রতারিত না হয়',
      'index.feat3.title': 'রিপোর্ট ও সাহায্য', 'index.feat3.body': 'আপনার অভিজ্ঞতা শেয়ার করুন এবং বিপজ্জনক প্রতারকদের চিনতে অন্যদের সাহায্য করুন',
      'footer.tagline': 'বাংলাদেশের জন্য একটি কমিউনিটি-চালিত প্রতারণা রিপোর্ট ও খোঁজার প্ল্যাটফর্ম।',
      'footer.search': 'খুঁজুন', 'footer.report': 'ঘটনা রিপোর্ট করুন', 'footer.admin': 'অ্যাডমিন প্যানেল',
      'footer.rights': '© ২০২৬ Fraud-Checker-BD। সর্বস্বত্ব সংরক্ষিত।',
      'index.modal.title': 'প্রতারণার ঘটনার বিবরণ', 'index.modal.full': 'সম্পূর্ণ বিবরণ দেখুন',
      'card.verified': 'রিপোর্টকৃত', 'card.loss': 'ক্ষতির পরিমাণ', 'card.item': 'যা হারিয়েছে', 'card.location': 'অবস্থান',
      'card.phone_hidden': 'ফোন দেখানো হয়নি', 'card.click': 'বিস্তারিত দেখতে ক্লিক করুন →',
      'card.unknown_scam': 'অজানা প্রতারণা', 'card.unknown_imposter': 'অজানা প্রতারক', 'card.location_na': 'অবস্থান দেওয়া হয়নি',
      'modal.fraudster': '🚩 রিপোর্টকৃত — অভিযুক্ত, যাচাই বাকি', 'modal.nickname': 'ডাকনাম', 'modal.fraud_details': '📋 প্রতারণার বিবরণ',
      'modal.scam_type': 'প্রতারণার ধরন', 'modal.item_lost': 'যা হারিয়েছে', 'modal.desc': '📝 ঘটনার বিবরণ',
      'modal.no_desc': 'কোনো বিবরণ দেওয়া হয়নি', 'modal.contact': '📞 যোগাযোগের তথ্য', 'modal.phones': 'ফোন নম্বর',
      'modal.reported_by': '👤 রিপোর্ট করেছেন', 'modal.reported_on': 'রিপোর্ট করা হয়েছে', 'modal.anonymous': 'পরিচয় গোপন',
      'modal.reporter_hidden': 'গোপন (রিপোর্টকারী পরিচয় দেখাতে চাননি)',
      'results.found_one': '{n}টি প্রতারণার রিপোর্ট পাওয়া গেছে', 'results.found_many': '{n}টি প্রতারণার রিপোর্ট পাওয়া গেছে',
      'verdict.has': '⚠️ এই নম্বরটি {n}টি প্রতারণার রিপোর্টে আছে। বিশ্বাস করার আগে নিচের বিবরণ দেখে নিন।',
      'verdict.none': '✅ এই নম্বরের বিরুদ্ধে কোনো প্রতারণার রিপোর্ট পাওয়া যায়নি। তবুও সতর্ক থাকুন — রিপোর্ট না থাকা মানেই নিরাপদ নয়।',
      'toast.enter_search': 'অনুগ্রহ করে একটি সার্চ টার্ম লিখুন',
      'toast.search_error': 'সার্চে সমস্যা', 'toast.event_not_found': 'ঘটনা পাওয়া যায়নি',
      'toast.detail_error': 'ঘটনার বিবরণ লোড করতে সমস্যা',

      'submit.title': 'প্রতারণার ঘটনা রিপোর্ট করুন', 'submit.subtitle': 'সব রিপোর্ট প্রকাশের আগে অ্যাডমিন কর্তৃক যাচাই করা হয়',
      'submit.sec1': 'প্রতারকের ব্যক্তিগত তথ্য', 'submit.sec2': 'প্রতারণার বিবরণ', 'submit.sec3': 'রিপোর্টকারীর তথ্য',
      'submit.picture': 'প্রতারকের ছবি', 'submit.picture_hint': 'প্রতারকের একটি ছবি আপলোড করুন (JPG, PNG, সর্বোচ্চ ৫MB)',
      'submit.name': 'প্রতারকের নাম', 'submit.name_hint': 'প্রতারকের যে নাম জানা আছে তার পুরো নাম',
      'submit.nickname': 'ডাকনাম / ছদ্মনাম', 'submit.nickname_hint': 'যে নামেও পরিচিত (ঐচ্ছিক)',
      'submit.phone': 'প্রতারকের ফোন নম্বর', 'submit.phone_hint': 'ফরম্যাট: +880XXXXXXXXX অথবা 01XXXXXXXXX',
      'submit.nid': 'এনআইডি / আইডি কার্ড নম্বর', 'submit.nid_hint': 'জাতীয় পরিচয়পত্র, পাসপোর্ট বা অন্য পরিচয়পত্রের নম্বর',
      'submit.social': 'সোশ্যাল মিডিয়া অ্যাকাউন্ট', 'submit.social_hint': 'প্রতারকের সোশ্যাল মিডিয়া প্রোফাইলের লিংক (ঐচ্ছিক)',
      'submit.address': 'প্রতারকের ঠিকানা', 'submit.address_hint': 'সর্বশেষ জানা ঠিকানা বা অবস্থান',
      'submit.scam_type': 'প্রতারণার ধরন', 'submit.scam_other': 'অন্য ধরন লিখুন…',
      'submit.loss_item': 'যা হারিয়েছেন / সম্পদ', 'submit.loss_other': 'অন্য কিছু লিখুন…',
      'submit.loss_amount': 'ক্ষতির পরিমাণ (টাকা)', 'submit.loss_amount_hint': 'বাংলাদেশি টাকায় আনুমানিক ক্ষতির পরিমাণ',
      'submit.desc': 'প্রতারণার বিবরণ', 'submit.desc_hint': 'বিস্তারিত বর্ণনা (৩০-৫০০ অক্ষর)',
      'submit.desc_ph': 'কী ঘটেছিল তা বর্ণনা করুন…', 'submit.char_count': 'অক্ষর সংখ্যা:', 'submit.char_warn': 'কমপক্ষে ৩০ অক্ষর প্রয়োজন',
      'submit.proof': 'প্রতারণার প্রমাণ', 'submit.proof_hint': 'স্ক্রিনশট, ছবি, ভিডিও বা ডকুমেন্ট (সর্বোচ্চ ২০টি ফাইল, প্রতিটি ১০MB)',
      'submit.proof_selected': 'নির্বাচিত: ০টি ফাইল', 'submit.proof_warn': 'সর্বোচ্চ ২০টি ফাইল অনুমোদিত। কিছু ফাইল সরান।',
      'submit.scam_loc': 'প্রতারণার অবস্থান', 'submit.scam_loc_hint': 'যেখানে প্রতারণাটি হয়েছে (অনলাইন প্ল্যাটফর্ম, স্থান ইত্যাদি)',
      'submit.scam_loc_ph': 'যেমন: Facebook, OLX, WhatsApp ইত্যাদি',
      'submit.gd': 'জেনারেল ডায়েরি (জিডি) নম্বর', 'submit.gd_hint': 'যদি থানায় জিডি/এফআইআর করা থাকে তার নম্বর',
      'submit.alt_phone': 'প্রতারকের বিকল্প ফোন নম্বর', 'submit.alt_phone_hint': 'প্রতারকের ব্যবহৃত অন্যান্য ফোন নম্বর',
      'submit.your_name': 'আপনার নাম', 'submit.your_name_hint': 'পুরো নাম বা ছদ্মনাম (জনসাধারণ থেকে গোপন রাখা যাবে)',
      'submit.your_phone': 'আপনার ফোন নম্বর', 'submit.your_phone_hint': 'পরবর্তী যোগাযোগের জন্য (ঐচ্ছিক)',
      'submit.your_email': 'আপনার ইমেইল', 'submit.your_email_hint': 'আপডেট ও নোটিফিকেশনের জন্য (ঐচ্ছিক)',
      'submit.hide': 'জনসাধারণের তালিকা থেকে আমার তথ্য গোপন রাখুন', 'submit.hide_hint': 'টিক দিলে আপনার রিপোর্ট জনসমক্ষে "পরিচয় গোপন" হিসেবে দেখানো হবে',
      'submit.back': '← খোঁজে ফিরে যান', 'submit.button': 'রিপোর্ট জমা দিন', 'submit.required': '(আবশ্যক)',
      'submit.success.title': 'রিপোর্ট জমা হয়েছে', 'submit.success.body': 'ধন্যবাদ — প্রকাশের আগে আমাদের টিম আপনার রিপোর্টটি যাচাই করবে।',
      'submit.success.ref': 'রেফারেন্স আইডি:', 'submit.success.search': 'ডেটাবেজে খুঁজুন', 'submit.success.another': 'আরেকটি রিপোর্ট করুন',
      'submit.toast.success': '✓ রিপোর্ট জমা হয়েছে', 'submit.toast.proof_required': 'অনুগ্রহ করে কমপক্ষে একটি প্রমাণ ফাইল আপলোড করুন',
      'submit.proof_selected_n': 'নির্বাচিত: {n}টি ফাইল', 'submit.dup': '⚠️ এই নম্বর/এনআইডির বিরুদ্ধে আগে থেকেই {n}টি রিপোর্ট আছে। আপনি তবুও জমা দিতে পারেন — এটি সত্যতা বাড়ায়।',
      'submit.phone_invalid': 'ফোন নম্বরের ফরম্যাট সঠিক নয়', 'submit.toast.invalid_alt': 'বিকল্প ফোন নম্বরের ফরম্যাট সঠিক নয়', 'submit.toast.invalid_rphone': 'রিপোর্টকারীর ফোন নম্বরের ফরম্যাট সঠিক নয়',
      'submit.toast.desc_len': 'বিবরণ ৩০ থেকে ৫০০ অক্ষরের মধ্যে হতে হবে', 'submit.toast.max_alt': 'সর্বোচ্চ ৫টি বিকল্প ফোন নম্বর অনুমোদিত', 'submit.toast.max_files': 'সর্বোচ্চ ২০টি ফাইল অনুমোদিত', 'submit.toast.error_prefix': 'সমস্যা', 'submit.toast.draft_restored': 'খসড়া পুনরুদ্ধার হয়েছে', 'submit.toast.submit_error': 'জমা দিতে সমস্যা',

      'detail.loading': 'ঘটনার বিবরণ লোড হচ্ছে…', 'detail.subtitle': 'রিপোর্টকৃত — যাচাই বাকি', 'detail.loss': 'ক্ষতির পরিমাণ', 'detail.scam_type': 'প্রতারণার ধরন', 'detail.location': 'অবস্থান',
      'detail.trust.count': 'এই নম্বরের রিপোর্ট সংখ্যা', 'detail.trust.first': 'প্রথম রিপোর্ট', 'detail.trust.last': 'সর্বশেষ রিপোর্ট',
      'detail.fraud_details': '📋 প্রতারণার বিবরণ', 'detail.item_lost': 'যা হারিয়েছে', 'detail.gd': 'জিডি নম্বর (পুলিশ)', 'detail.desc': 'বিবরণ',
      'detail.imposter': '👤 প্রতারকের প্রোফাইলের বিবরণ', 'detail.full_name': 'পুরো নাম', 'detail.nickname': 'ডাকনাম / ছদ্মনাম',
      'detail.primary_phone': 'প্রধান ফোন', 'detail.nid': 'এনআইডি / আইডি নম্বর', 'detail.alt_phones': 'বিকল্প ফোন নম্বর',
      'detail.address': 'ঠিকানা / অবস্থান', 'detail.social': 'সোশ্যাল মিডিয়া অ্যাকাউন্ট', 'detail.profile_link': '👤 প্রতারকের সম্পূর্ণ প্রোফাইল দেখুন →',
      'detail.evidence': '📸 প্রমাণ ও দলিল', 'detail.reported_by': '📢 রিপোর্ট করেছেন', 'detail.share': '🔗 এই রিপোর্ট শেয়ার করুন',
      'detail.share_body': 'এই প্রতারণার রিপোর্ট শেয়ার করে অন্যদের নিরাপদ থাকতে সাহায্য করুন:', 'detail.copy': 'লিংক কপি করুন',
      'detail.dispute.title': '⚖️ এই রিপোর্টটি কি ভুল?',
      'detail.dispute.body': 'আপনি যদি এখানে নামকৃত ব্যক্তি হন, অথবা আপনার কাছে এই রিপোর্ট ভুল প্রমাণ করার তথ্য থাকে, তাহলে আপত্তি জমা দিন; আমাদের মডারেটররা তা যাচাই করবেন।',
      'detail.dispute.button': 'এই রিপোর্টে আপত্তি জানান', 'detail.dispute.reason_ph': 'কেন এই রিপোর্টটি ভুল তা ব্যাখ্যা করুন (২০–১০০০ অক্ষর)…',
      'detail.dispute.contact_ph': 'আপনার যোগাযোগ (ঐচ্ছিক, পরবর্তী যোগাযোগের জন্য)', 'detail.dispute.submit': 'আপত্তি জমা দিন',
      'detail.notfound.title': 'ঘটনা পাওয়া যায়নি', 'detail.notfound.body': 'এই প্রতারণার রিপোর্টটি পাওয়া যায়নি বা সরিয়ে ফেলা হতে পারে।',
      'detail.notfound.button': 'খোঁজে ফিরে যান',
      'detail.reporter_public': 'রিপোর্টকারীর তথ্য প্রকাশ্য', 'detail.reporter_private': 'রিপোর্টকারীর তথ্য গোপন (রিপোর্টকারীর অনুরোধে)',
      'detail.not_filed': 'করা হয়নি', 'detail.gd_not_filed': 'করা হয়নি', 'detail.download': 'খুলুন / ডাউনলোড করুন', 'detail.download_video': 'ভিডিও খুলুন / ডাউনলোড করুন',
      'toast.link_copied': 'লিংক কপি হয়েছে', 'toast.copy_fail': 'লিংক কপি করা যায়নি', 'toast.dispute_min': 'অনুগ্রহ করে কমপক্ষে ২০ অক্ষর লিখুন।',

      'profile.loading': 'প্রতারকের প্রোফাইল লোড হচ্ছে…', 'profile.verified_profile': 'রিপোর্টকৃত — কমিউনিটির অভিযোগ, যাচাই বাকি',
      'profile.total': 'মোট ঘটনা', 'profile.total_loss': 'মোট ক্ষতি', 'profile.last_active': 'সর্বশেষ সক্রিয়', 'profile.status': 'প্রোফাইলের অবস্থা',
      'profile.status_verified': '🚩 রিপোর্টকৃত', 'profile.contact': '📱 জানা যোগাযোগের তথ্য', 'profile.details': 'ℹ️ প্রোফাইলের বিবরণ',
      'profile.history': '🔴 প্রতারণার ঘটনার ইতিহাস', 'profile.warn.title': '⚠️ সতর্ক থাকুন',
      'profile.warn.body': 'এই ব্যক্তির সাথে দেখা হলে টাকা পাঠাবেন না, ব্যক্তিগত তথ্য শেয়ার করবেন না বা কোনো আর্থিক লেনদেন করবেন না। নতুন কোনো ঘটনা সাথে সাথে রিপোর্ট করুন।',
      'profile.warn.button': 'এই ব্যক্তির বিরুদ্ধে নতুন ঘটনা রিপোর্ট করুন',
      'profile.notfound.title': 'প্রোফাইল পাওয়া যায়নি', 'profile.notfound.body': 'এই প্রতারকের প্রোফাইল পাওয়া যায়নি বা সরিয়ে ফেলা হতে পারে।',
      'profile.no_incidents': 'এই প্রোফাইলের সাথে এখনো কোনো প্রকাশ্য ঘটনা যুক্ত নেই।',
      'profile.full_name': 'পুরো নাম', 'profile.nickname': 'ডাকনাম / ছদ্মনাম', 'profile.known_address': 'জানা ঠিকানা', 'profile.social': 'সোশ্যাল মিডিয়া',
      'profile.unknown': 'অজানা', 'profile.unknown_fraudster': 'অজানা প্রতারক', 'profile.phones': 'ফোন নম্বর ({n})', 'profile.no_phones': 'কোনো ফোন নম্বর পাওয়া যায়নি', 'profile.nids': 'এনআইডি নম্বর ({n})',

      'admin.title': 'Fraud-Checker-BD অ্যাডমিন', 'admin.portal': 'নিরাপদ মডারেটর অ্যাক্সেস পোর্টাল',
      'admin.user_ph': 'অ্যাডমিন ইউজারনেম', 'admin.pass_ph': 'পাসওয়ার্ড', 'admin.login': 'লগইন', 'admin.logout': 'লগআউট',
      'admin.panel.title': 'Fraud-Checker-BD কন্ট্রোল প্যানেল', 'admin.panel.sub': 'কেন্দ্রীয় প্রশাসন ও মডারেশন কেন্দ্র',
      'admin.tab.live': '✓ লাইভ ঘটনা', 'admin.tab.pending': '⏳ অপেক্ষমাণ ঘটনা', 'admin.tab.deleted': '✕ মুছে ফেলা ঘটনা',
      'admin.tab.imposters': '👥 প্রতারকের তালিকা', 'admin.tab.reporters': '📋 রিপোর্টকারীর তালিকা', 'admin.tab.audit': '📜 অডিট লগ',
      'admin.tab.disputes': '⚖️ আপত্তি', 'admin.tab.admins': '🔑 অ্যাডমিন তালিকা',
      'admin.filter_ph': 'বর্তমান তালিকা ফিল্টার করুন…',
      'admin.live.title': 'লাইভ প্রতারণার ঘটনা', 'admin.live.sub': 'অনুমোদিত ঘটনা যা এখন প্রকাশ্য ডেটাবেজে আছে',
      'admin.pending.title': 'অপেক্ষমাণ প্রতারণার ঘটনা', 'admin.pending.sub': 'অ্যাডমিন যাচাই ও অনুমোদনের অপেক্ষায় থাকা ঘটনা',
      'admin.deleted.title': 'মুছে ফেলা প্রতারণার ঘটনা', 'admin.deleted.sub': 'কারণ ও সময়সহ বাতিল করা ঘটনা',
      'admin.imposters.title': 'প্রতারকের ডেটাবেজ', 'admin.imposters.sub': 'শনাক্ত ও যাচাইকৃত প্রতারকদের সম্পূর্ণ তালিকা',
      'admin.reporters.title': 'রিপোর্টকারীদের অবদান', 'admin.reporters.sub': 'কমিউনিটির সদস্য ও তাদের জমা দেওয়া রিপোর্ট',
      'admin.audit.title': 'মডারেশন অডিট লগ', 'admin.audit.sub': 'প্রতিটি অনুমোদন / বাতিল / মুছে ফেলা / সম্পাদনা, সর্বশেষটি আগে',
      'admin.disputes.title': 'আপত্তি', 'admin.disputes.sub': 'প্রকাশিত রিপোর্টের বিরুদ্ধে জমা দেওয়া আপত্তি',
      'admin.admins.title': 'অ্যাডমিন ব্যবস্থাপনা', 'admin.admins.sub': 'সিস্টেম অ্যাডমিন (শুধু সুপারইউজার অ্যাকাউন্ট যোগ বা সরাতে পারে)',
      'admin.add_admin': 'একজন অ্যাডমিন যোগ করুন', 'admin.username_ph': 'ইউজারনেম', 'admin.password_ph2': 'পাসওয়ার্ড (কমপক্ষে ৮)', 'admin.create': 'তৈরি করুন',
      'admin.bulk.approve': 'নির্বাচিতগুলো অনুমোদন করুন', 'admin.bulk.reject': 'নির্বাচিতগুলো বাতিল করুন', 'admin.bulk.selected': '{n}টি নির্বাচিত',
      'admin.modal.title': 'ঘটনার বিবরণ', 'admin.approve': 'অনুমোদন', 'admin.reject': 'বাতিল', 'admin.delete': 'মুছুন',
      'admin.reapprove': 'পুনরায় অনুমোদন', 'admin.edit': 'সম্পাদনা', 'admin.remove': 'সরান', 'admin.select': 'নির্বাচন',
      'admin.empty.live': 'এই মুহূর্তে কোনো লাইভ ঘটনা নেই', 'admin.empty.pending': 'কোনো অপেক্ষমাণ ঘটনা নেই', 'admin.empty.deleted': 'কোনো মুছে ফেলা ঘটনা নেই',
      'admin.empty.imposters': 'ডেটাবেজে কোনো প্রতারক নেই', 'admin.empty.reporters': 'এখনো কোনো রিপোর্টকারী নেই', 'admin.empty.audit': 'এখনো কোনো অডিট এন্ট্রি নেই',
      'admin.empty.disputes': 'কোনো আপত্তি নেই', 'admin.empty.admins': 'কোনো অ্যাডমিন নেই।', 'admin.loadmore': 'আরও দেখুন',
      'admin.stat.pending': 'অপেক্ষমাণ', 'admin.stat.live': 'লাইভ', 'admin.stat.rejected': 'বাতিল', 'admin.stat.fraudsters': 'প্রতারক', 'admin.stat.loss': 'মোট ক্ষতি', 'admin.stat.new7': 'নতুন (৭ দিন)',
      'admin.live_since': 'লাইভ আছে {t}', 'admin.submitted': 'জমা: {t}', 'admin.rejected_ago': 'বাতিল {t}', 'admin.reason': 'কারণ: {x}', 'admin.approved_at': 'অনুমোদিত: {t}', 'admin.awaiting': 'পদক্ষেপের অপেক্ষায়…',
      'admin.loss': 'ক্ষতি', 'admin.scams': 'প্রতারণা', 'admin.total_loss': 'মোট ক্ষতি', 'admin.last_active': 'সর্বশেষ সক্রিয়', 'admin.reports': 'রিপোর্ট', 'admin.approved_n': 'অনুমোদিত', 'admin.first_report': 'প্রথম রিপোর্ট', 'admin.view_profile': '↗ প্রোফাইল দেখুন', 'admin.not_specified': 'উল্লেখ নেই',
      'admin.badge.live': 'লাইভ', 'admin.badge.pending': 'অপেক্ষমাণ', 'admin.badge.rejected': 'বাতিল', 'admin.card.select': 'নির্বাচন',
      'admin.m.imposter': '👤 প্রতারকের তথ্য', 'admin.m.scam': '🎯 প্রতারণার তথ্য', 'admin.m.evidence': '📸 প্রমাণ', 'admin.m.reporter': '📋 রিপোর্টকারীর তথ্য', 'admin.m.status': '📊 ঘটনার অবস্থা',
      'admin.f.name': 'নাম', 'admin.f.nickname': 'ডাকনাম', 'admin.f.phone': 'ফোন', 'admin.f.nid': 'এনআইডি', 'admin.f.address': 'ঠিকানা', 'admin.f.social': 'সোশ্যাল মিডিয়া', 'admin.f.altphones': 'বিকল্প ফোন নম্বর', 'admin.f.type': 'ধরন', 'admin.f.lossitem': 'খোয়ানো বস্তু', 'admin.f.lossamount': 'ক্ষতির পরিমাণ', 'admin.f.location': 'স্থান', 'admin.f.gd': 'জিডি নম্বর', 'admin.f.desc': 'বিবরণ', 'admin.f.visibility': 'দৃশ্যমানতা', 'admin.f.email': 'ইমেইল', 'admin.f.submitted': 'জমা', 'admin.f.status': 'অবস্থা', 'admin.f.approved': 'অনুমোদিত', 'admin.f.rejected': 'বাতিল', 'admin.f.reason': 'কারণ', 'admin.f.photo': 'প্রতারকের ছবি', 'admin.f.prooffiles': 'প্রমাণ ফাইল ({n})',
      'admin.no_proofs': 'কোনো প্রমাণ ফাইল সংযুক্ত করা হয়নি।', 'admin.no_photo': 'প্রতারকের কোনো ছবি আপলোড করা হয়নি।',
      'admin.btn.close': 'বন্ধ করুন', 'admin.btn.cancel': 'বাতিল', 'admin.btn.save': 'পরিবর্তন সংরক্ষণ করুন',
      'admin.au.by': 'দ্বারা', 'admin.au.fields': 'ক্ষেত্র:',
      'admin.dc.re': 'প্রসঙ্গ:', 'admin.dc.contact': 'যোগাযোগ:', 'admin.dc.resolve': 'নিষ্পত্তি করুন', 'admin.dc.dismiss': 'খারিজ করুন', 'admin.dc.note': 'নোট:', 'admin.st.open': 'খোলা', 'admin.st.resolved': 'নিষ্পন্ন', 'admin.st.dismissed': 'খারিজ',
      'admin.am.created': 'তৈরি', 'admin.am.remove': 'সরান',
      'admin.edit.title': '✏️ ঘটনা সম্পাদনা', 'admin.edit.desc': 'বিবরণ (৩০–৫০০ অক্ষর)',
      'admin.toast.session': 'আপনার অ্যাডমিন সেশন শেষ হয়ে গেছে। অনুগ্রহ করে আবার লগইন করুন।', 'admin.toast.network': 'নেটওয়ার্ক সমস্যা', 'admin.toast.login_err': 'লগইন সমস্যা', 'admin.toast.invalid_creds': 'ভুল তথ্য', 'admin.toast.event_not_found': 'ঘটনা পাওয়া যায়নি', 'admin.toast.ureq': 'ইউজারনেম এবং পাসওয়ার্ড আবশ্যক', 'admin.toast.confirm_remove': 'অ্যাডমিন "{u}" সরাবেন?',
      'admin.reject_prompt': 'বাতিলের কারণ লিখুন:', 'admin.delete_confirm': 'আপনি কি নিশ্চিত এই ঘটনাটি মুছে ফেলতে চান?', 'admin.note_prompt': 'ঐচ্ছিক নোট:', 'admin.bulk_reject_prompt': '{n}টি ঘটনার জন্য বাতিলের কারণ:', 'admin.bulk_confirm_approve': '{n}টি ঘটনা অনুমোদন করবেন?', 'admin.bulk_confirm_reject': '{n}টি ঘটনা বাতিল করবেন?', 'admin.selected_n': '{n}টি নির্বাচিত', 'admin.bulk_done_approve': '{ok}/{total} অনুমোদিত', 'admin.bulk_done_reject': '{ok}/{total} বাতিল', 'admin.au.action': 'কাজ', 'admin.au.system': 'সিস্টেম',

      // allegation framing + new features (BN)
      'common.allegation': '⚠️ কমিউনিটির অভিযোগ — একজন ব্যবহারকারী রিপোর্ট করেছেন, স্বাধীনভাবে যাচাই এখনো হয়নি। এটি প্রমাণিত সত্য বা আদালতের রায় নয়।',
      'index.risk.title': 'আমি কি প্রতারিত হচ্ছি? একটি নম্বর যাচাই করুন',
      'index.risk.sub': 'কোনো ফোন বা বিকাশ/নগদ নম্বর দিন — রিপোর্ট আছে কিনা দেখুন।',
      'index.risk.check': 'এখনই যাচাই করুন', 'index.risk.reports': '{n}টি রিপোর্ট', 'index.risk.clean': 'এখনো কোনো রিপোর্ট নেই — তবুও সতর্ক থাকুন।',
      'index.risk.foreign': 'এটি একটি বিদেশি / অস্বাভাবিক নম্বর। ব্যাংক বা এমএফএস কখনো এমন নম্বর থেকে কল করে না।',
      'index.recent.title': 'সাম্প্রতিক রিপোর্ট', 'index.recent.sub': 'সর্বশেষ অনুমোদিত কমিউনিটি প্রতারণা রিপোর্ট',
      'submit.mfs': '💸 টাকার হদিস (বিকাশ / নগদ / ব্যাংক)',
      'submit.mfs_hint': 'আপনি যদি টাকা পাঠিয়ে থাকেন, কোথায় গেছে তা যোগ করুন — সিম বদলালেও প্রাপক ওয়ালেট/অ্যাকাউন্টই প্রতারক ধরার সবচেয়ে শক্ত সূত্র।',
      'submit.mfs_provider': '-- এমএফএস প্রোভাইডার --', 'submit.mfs_wallet': 'প্রাপক ওয়ালেট নম্বর', 'submit.mfs_trxid': 'ট্রানজেকশন আইডি (TrxID)', 'submit.bank': 'ব্যাংক অ্যাকাউন্ট (নাম / নম্বর)',
      'submit.paste': '⚡ দ্রুত শুরু — প্রতারণার এসএমএস / বার্তা পেস্ট করুন',
      'submit.paste_hint': 'আমরা ফোন নম্বর, ওয়ালেট নম্বর, ট্রানজেকশন আইডি ও পরিমাণ বের করে দেব। জমা দেওয়ার আগে সব সম্পাদনা করতে পারবেন।',
      'submit.paste_ph': 'আপনি যে বার্তা পেয়েছেন তা পেস্ট করুন…', 'submit.paste_btn': 'তথ্য বের করুন',
      'submit.paste.phone': 'ফোন', 'submit.paste.trxid': 'ট্রানজেকশন আইডি', 'submit.paste.desc': 'বিবরণ',
      'submit.paste.done': 'পূরণ হয়েছে: {items}। জমা দেওয়ার আগে দেখে নিন।', 'submit.paste.none': 'চেনার মতো কিছু পাওয়া যায়নি — অনুগ্রহ করে নিজে পূরণ করুন।',
      'submit.consent': 'আমি নিজে এই ঘটনার শিকার (বা প্রত্যক্ষদর্শী), প্রমাণ সত্য, এবং আমি বুঝি যে এই রিপোর্টে একজন প্রকৃত ব্যক্তির নাম আছে এবং মডারেটররা এটি যাচাই করতে পারেন।',
      'submit.consent_pii': '⚠ আপনার বিবরণে আপনার নিজের ফোন/এনআইডি আছে বলে মনে হচ্ছে — জমা দেওয়ার আগে আপনার ব্যক্তিগত তথ্য সরিয়ে ফেলুন।',
      'submit.toast.consent': 'অনুগ্রহ করে নিশ্চিত করুন রিপোর্টটি সত্য ও প্রত্যক্ষ।',
      'submit.strength': 'রিপোর্টের শক্তি', 'submit.strength.add': '{items} যোগ করলে রিপোর্টটি আরও শক্তিশালী হবে।', 'submit.strength.good': 'শক্তিশালী রিপোর্ট — ধন্যবাদ!',
      'submit.need.proof': 'আরও প্রমাণ ফাইল', 'submit.need.photo': 'একটি ছবি', 'submit.need.gd': 'জিডি নম্বর', 'submit.need.nid': 'এনআইডি', 'submit.need.desc': 'আরও বিস্তারিত বিবরণ', 'submit.need.mfs': 'টাকার হদিস',
      'detail.risk': 'ঝুঁকির মাত্রা', 'detail.share.wa': 'হোয়াটসঅ্যাপ', 'detail.share.fb': 'ফেসবুক', 'detail.share.native': 'শেয়ার',
      'detail.share.msg': '⚠️ Fraud-Checker-BD থেকে প্রতারণা সতর্কতা (কমিউনিটির অভিযোগ, যাচাই বাকি):',
      'detail.golden.title': '⏱️ এইমাত্র টাকা পাঠিয়েছেন? দ্রুত ব্যবস্থা নিন',
      'detail.golden.body': 'সাথে সাথে প্রোভাইডারের সাথে যোগাযোগ করলে কখনো কখনো এমএফএস লেনদেন আটকানো যায়। প্রাপক ওয়ালেট, TrxID, পরিমাণ ও সময় জানান।',
      'detail.golden.bkash': 'বিকাশ: ১৬২৪৭', 'detail.golden.nagad': 'নগদ: ১৬১৬৭', 'detail.golden.police': 'পুলিশ / জরুরি: ৯৯৯ · সাইবার সহায়তা: সিআইডি সাইবার পুলিশ সেন্টার',
      'admin.change_pw': 'পাসওয়ার্ড পরিবর্তন', 'admin.pw.title': 'আপনার পাসওয়ার্ড পরিবর্তন করুন', 'admin.pw.current': 'বর্তমান পাসওয়ার্ড', 'admin.pw.new': 'নতুন পাসওয়ার্ড (কমপক্ষে ৮)', 'admin.pw.save': 'পাসওয়ার্ড পরিবর্তন করুন', 'admin.pw.required': 'উভয় ঘর পূরণ আবশ্যক।', 'admin.pw.must_change': 'আপনি ডিফল্ট পাসওয়ার্ড ব্যবহার করছেন। এখনই পরিবর্তন করুন।',
      'admin.toast.media_err': 'ফাইলটি লোড করা যায়নি।', 'admin.sort.evidence': '⚠ সাজান: দুর্বল প্রমাণ আগে', 'admin.evidence': 'প্রমাণ'
    }
  };

  var lang = (function () { try { return localStorage.getItem(STORE) || 'bn'; } catch (e) { return 'bn'; } })();

  function t(key, vars) {
    var dict = I18N[lang] || I18N.en;
    var s = dict[key];
    if (s == null) s = I18N.en[key];
    if (s == null) s = key;
    if (vars) { Object.keys(vars).forEach(function (k) { s = s.split('{' + k + '}').join(vars[k]); }); }
    return s;
  }
  function setAttrAll(root, attr, fn) {
    var els = root.querySelectorAll('[' + attr + ']');
    for (var i = 0; i < els.length; i++) fn(els[i], els[i].getAttribute(attr));
  }
  function applyI18n(root) {
    root = root || document;
    setAttrAll(root, 'data-i18n', function (el, key) { el.textContent = t(key); });
    setAttrAll(root, 'data-i18n-html', function (el, key) { el.innerHTML = t(key); });
    setAttrAll(root, 'data-i18n-ph', function (el, key) { el.setAttribute('placeholder', t(key)); });
    setAttrAll(root, 'data-i18n-aria', function (el, key) { el.setAttribute('aria-label', t(key)); });
    if (document.documentElement) document.documentElement.lang = lang;
    updateToggle();
  }
  function updateToggle() {
    var label = (lang === 'bn') ? 'English' : 'বাংলা';
    var btns = document.querySelectorAll('[id^="lang-toggle"]');
    for (var i = 0; i < btns.length; i++) btns[i].textContent = label;
  }
  function setLang(l) {
    lang = (l === 'en') ? 'en' : 'bn';
    try { localStorage.setItem(STORE, lang); } catch (e) { /* ignore */ }
    applyI18n(document);
    document.dispatchEvent(new CustomEvent('fc:langchange', { detail: { lang: lang } }));
  }
  function toggleLang() { setLang(lang === 'bn' ? 'en' : 'bn'); }

  function init() { applyI18n(document); }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
  else init();

  var FC = global.FC = global.FC || {};
  FC.t = t; FC.applyI18n = applyI18n; FC.setLang = setLang; FC.toggleLang = toggleLang;
  Object.defineProperty(FC, 'lang', { get: function () { return lang; }, configurable: true });
})(window);
